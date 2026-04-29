/**
 * TaskFlow — Lambda handler (DynamoDB backend)
 * Runtime: Node.js 20 (ESM)
 *
 * Single-table DynamoDB design:
 *   PK = "WORKSPACE#<accountId>-<env>"   (constant — set by SAM from AWS::AccountId)
 *   SK = "<TYPE>#<id>"
 *   Types: CAT · PROJ · TASK · SUB · COM
 *
 * getState: one Query(PK) returns all workspace items → assembled in memory.
 * Mutations: direct PutItem / UpdateItem / DeleteItem using PK + SK.
 *
 * Environment variables (set automatically by SAM):
 *   TABLE_NAME   — DynamoDB table name
 *   WORKSPACE_ID — "<AccountId>-<Environment>" e.g. "123456789012-prod"
 */

import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  QueryCommand,
  PutCommand,
  UpdateCommand,
  DeleteCommand,
  BatchWriteCommand,
} from '@aws-sdk/lib-dynamodb';

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}), {
  marshallOptions:   { removeUndefinedValues: true },
  unmarshallOptions: { wrapNumbers: false },
});

const TABLE = process.env.TABLE_NAME;
const WID   = process.env.WORKSPACE_ID;
const PK    = `WORKSPACE#${WID}`;

// ─── HELPERS ─────────────────────────────────────────────────────────────────

function uid() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2);
}

// Paginated Query — fetches ALL items in the workspace (handles >1 MB pages)
async function queryAll() {
  const items = [];
  let lastKey;
  do {
    const res = await ddb.send(new QueryCommand({
      TableName: TABLE,
      KeyConditionExpression: 'PK = :pk',
      ExpressionAttributeValues: { ':pk': PK },
      ExclusiveStartKey: lastKey,
    }));
    items.push(...(res.Items || []));
    lastKey = res.LastEvaluatedKey;
  } while (lastKey);
  return items;
}

// BatchDelete array of SK strings (handles >25-item DynamoDB limit in chunks)
async function batchDelete(sks) {
  if (!sks.length) return;
  for (let i = 0; i < sks.length; i += 25) {
    const chunk = sks.slice(i, i + 25);
    await ddb.send(new BatchWriteCommand({
      RequestItems: {
        [TABLE]: chunk.map(sk => ({ DeleteRequest: { Key: { PK, SK: sk } } })),
      },
    }));
  }
}

// ─── RESPONSE / CORS ─────────────────────────────────────────────────────────

const ok  = body   => ({ statusCode: 200, headers: cors(), body: JSON.stringify(body) });
const err = (s, m) => ({ statusCode: s,   headers: cors(), body: JSON.stringify({ error: m }) });

function cors() {
  return {
    'Content-Type':                 'application/json',
    'Access-Control-Allow-Origin':  'https://protozoa.amazon.dev',
    'Access-Control-Allow-Headers': 'Authorization,Content-Type',
    'Access-Control-Allow-Methods': 'GET,POST,PATCH,DELETE,OPTIONS',
  };
}

// ─── AUTH ─────────────────────────────────────────────────────────────────────

function getUserId(event) {
  return event.requestContext?.authorizer?.jwt?.claims?.sub || null;
}

// ─── GET STATE ───────────────────────────────────────────────────────────────

async function getState() {
  const items = await queryAll();

  const categories = [];
  const projects   = [];
  const taskMap    = {};   // id → task object (with empty subtasks/comments arrays)
  const subMap     = {};   // taskId → subtask[]
  const comMap     = {};   // taskId → comment[]

  for (const item of items) {
    const sk = item.SK;
    if (sk.startsWith('CAT#')) {
      categories.push({ id: item.id, name: item.name, icon: item.icon, collapsed: item.collapsed ?? false });
    } else if (sk.startsWith('PROJ#')) {
      projects.push({ id: item.id, categoryId: item.categoryId || null, name: item.name, color: item.color, tasks: [] });
    } else if (sk.startsWith('TASK#')) {
      taskMap[item.id] = {
        id: item.id, projectId: item.projectId,
        title: item.title, status: item.status,
        assignee: item.assignee || '', dueDate: item.dueDate || '',
        subtasks: [], comments: [],
      };
    } else if (sk.startsWith('SUB#')) {
      (subMap[item.taskId] = subMap[item.taskId] || []).push(
        { id: item.id, title: item.title, done: item.done ?? false }
      );
    } else if (sk.startsWith('COM#')) {
      (comMap[item.taskId] = comMap[item.taskId] || []).push(
        { id: item.id, author: item.author, text: item.text, ts: item.ts }
      );
    }
  }

  // Attach subtasks + comments to their tasks
  for (const t of Object.values(taskMap)) {
    t.subtasks = subMap[t.id] || [];
    t.comments = comMap[t.id] || [];
  }

  // Attach tasks to their projects
  const projMap = {};
  for (const p of projects) projMap[p.id] = p;
  for (const t of Object.values(taskMap)) {
    if (projMap[t.projectId]) projMap[t.projectId].tasks.push(t);
  }

  return ok({ categories, projects });
}

// ─── CATEGORY HANDLERS ───────────────────────────────────────────────────────

async function createCategory({ name, icon = 'folder' }) {
  if (!name?.trim()) return err(400, 'name is required');
  const id = uid();
  await ddb.send(new PutCommand({
    TableName: TABLE,
    Item: { PK, SK: `CAT#${id}`, id, name: name.trim(), icon, collapsed: false, createdAt: new Date().toISOString() },
  }));
  return ok({ id });
}

async function updateCategory(catId, { name, icon, collapsed }) {
  const exprs = [], names = {}, vals = {};
  if (name      !== undefined) { exprs.push('#nm = :name'); names['#nm'] = 'name'; vals[':name'] = name; }
  if (icon      !== undefined) { exprs.push('icon = :icon');                        vals[':icon'] = icon; }
  if (collapsed !== undefined) { exprs.push('collapsed = :col');                    vals[':col']  = collapsed; }
  if (!exprs.length) return ok({});
  await ddb.send(new UpdateCommand({
    TableName: TABLE,
    Key: { PK, SK: `CAT#${catId}` },
    UpdateExpression: `SET ${exprs.join(', ')}`,
    ExpressionAttributeNames:  Object.keys(names).length ? names : undefined,
    ExpressionAttributeValues: vals,
  }));
  return ok({});
}

// ─── PROJECT HANDLERS ────────────────────────────────────────────────────────

async function createProject({ name, color = '#f59e0b', categoryId }) {
  if (!name?.trim()) return err(400, 'name is required');
  const id = uid();
  await ddb.send(new PutCommand({
    TableName: TABLE,
    Item: { PK, SK: `PROJ#${id}`, id, name: name.trim(), color, categoryId: categoryId || null, createdAt: new Date().toISOString() },
  }));
  return ok({ id });
}

async function updateProject(projId, { name, color, categoryId }) {
  const exprs = [], names = {}, vals = {};
  if (name       !== undefined) { exprs.push('#nm = :name');    names['#nm'] = 'name'; vals[':name']  = name; }
  if (color      !== undefined) { exprs.push('color = :color');                        vals[':color'] = color; }
  if (categoryId !== undefined) { exprs.push('categoryId = :cat');                     vals[':cat']   = categoryId || null; }
  if (!exprs.length) return ok({});
  await ddb.send(new UpdateCommand({
    TableName: TABLE,
    Key: { PK, SK: `PROJ#${projId}` },
    UpdateExpression: `SET ${exprs.join(', ')}`,
    ExpressionAttributeNames:  Object.keys(names).length ? names : undefined,
    ExpressionAttributeValues: vals,
  }));
  return ok({});
}

async function deleteProject(projId) {
  // Cascade: delete the project + all its tasks + those tasks' subtasks & comments
  const items   = await queryAll();
  const taskIds = items.filter(i => i.SK.startsWith('TASK#') && i.projectId === projId).map(i => i.id);
  const toDelete = [`PROJ#${projId}`];
  for (const item of items) {
    if (item.SK.startsWith('TASK#') && item.projectId === projId) toDelete.push(item.SK);
    if ((item.SK.startsWith('SUB#') || item.SK.startsWith('COM#')) && taskIds.includes(item.taskId)) toDelete.push(item.SK);
  }
  await batchDelete(toDelete);
  return ok({});
}

// ─── TASK HANDLERS ───────────────────────────────────────────────────────────

async function createTask(projId, { title = 'New Task' }) {
  const id = uid();
  await ddb.send(new PutCommand({
    TableName: TABLE,
    Item: {
      PK, SK: `TASK#${id}`, id, projectId: projId,
      title, status: 'todo', assignee: '', dueDate: null,
      createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
    },
  }));
  return ok({ id });
}

async function updateTask(taskId, { title, status, assignee, dueDate }) {
  if (status !== undefined && !['todo','inprogress','done'].includes(status)) return err(400, 'Invalid status');
  const now = new Date().toISOString();
  const exprs = ['updatedAt = :ua'], names = {}, vals = { ':ua': now };
  if (title    !== undefined) { exprs.push('#tt = :title');  names['#tt'] = 'title';  vals[':title']  = title; }
  if (status   !== undefined) { exprs.push('#st = :status'); names['#st'] = 'status'; vals[':status'] = status; }
  if (assignee !== undefined) { exprs.push('assignee = :asgn');                        vals[':asgn']   = assignee; }
  if (dueDate  !== undefined) { exprs.push('dueDate = :dd');                           vals[':dd']     = dueDate || null; }
  await ddb.send(new UpdateCommand({
    TableName: TABLE,
    Key: { PK, SK: `TASK#${taskId}` },
    UpdateExpression: `SET ${exprs.join(', ')}`,
    ExpressionAttributeNames:  Object.keys(names).length ? names : undefined,
    ExpressionAttributeValues: vals,
  }));
  return ok({});
}

async function deleteTask(taskId) {
  // Cascade: delete task + its subtasks + comments
  const items    = await queryAll();
  const toDelete = [`TASK#${taskId}`];
  for (const item of items) {
    if ((item.SK.startsWith('SUB#') || item.SK.startsWith('COM#')) && item.taskId === taskId) {
      toDelete.push(item.SK);
    }
  }
  await batchDelete(toDelete);
  return ok({});
}

// ─── SUBTASK HANDLERS ────────────────────────────────────────────────────────

async function addSubtask(taskId, { title }) {
  if (!title?.trim()) return err(400, 'title is required');
  const id = uid();
  await ddb.send(new PutCommand({
    TableName: TABLE,
    Item: { PK, SK: `SUB#${id}`, id, taskId, title: title.trim(), done: false, createdAt: new Date().toISOString() },
  }));
  return ok({ id });
}

async function updateSubtask(subId, { done, title }) {
  const exprs = [], names = {}, vals = {};
  if (done  !== undefined) { exprs.push('done = :done');        vals[':done']  = done; }
  if (title !== undefined) { exprs.push('#tt = :title'); names['#tt'] = 'title'; vals[':title'] = title; }
  if (!exprs.length) return ok({});
  await ddb.send(new UpdateCommand({
    TableName: TABLE,
    Key: { PK, SK: `SUB#${subId}` },
    UpdateExpression: `SET ${exprs.join(', ')}`,
    ExpressionAttributeNames:  Object.keys(names).length ? names : undefined,
    ExpressionAttributeValues: vals,
  }));
  return ok({});
}

async function deleteSubtask(subId) {
  await ddb.send(new DeleteCommand({ TableName: TABLE, Key: { PK, SK: `SUB#${subId}` } }));
  return ok({});
}

// ─── COMMENT HANDLERS ────────────────────────────────────────────────────────

async function addComment(taskId, { author, text }) {
  if (!text?.trim()) return err(400, 'text is required');
  const id = uid();
  await ddb.send(new PutCommand({
    TableName: TABLE,
    Item: {
      PK, SK: `COM#${id}`, id, taskId,
      author: (author || 'Anonymous').trim(),
      text: text.trim(),
      ts: Date.now(),
      createdAt: new Date().toISOString(),
    },
  }));
  return ok({ id });
}

// ─── MAIN HANDLER ────────────────────────────────────────────────────────────

export const handler = async (event) => {
  // CORS pre-flight
  if (event.requestContext.http.method === 'OPTIONS') {
    return { statusCode: 200, headers: cors(), body: '' };
  }

  const userId = getUserId(event);
  if (!userId) return err(401, 'Unauthorized');

  const method   = event.requestContext.http.method;
  const path     = event.rawPath || event.requestContext.http.path;
  const body     = event.body ? JSON.parse(event.body) : {};
  const segments = path.split('/');   // ['', 'tasks', ':id', 'subtasks']

  try {
    if (method === 'GET'    && path === '/state')                                            return getState();
    if (method === 'POST'   && path === '/categories')                                       return createCategory(body);
    if (method === 'PATCH'  && segments[1] === 'categories' && segments[2])                  return updateCategory(segments[2], body);
    if (method === 'POST'   && path === '/projects')                                         return createProject(body);
    if (method === 'PATCH'  && segments[1] === 'projects' && segments[2] && !segments[3])    return updateProject(segments[2], body);
    if (method === 'DELETE' && segments[1] === 'projects' && segments[2] && !segments[3])    return deleteProject(segments[2]);
    if (method === 'POST'   && segments[1] === 'projects' && segments[3] === 'tasks')        return createTask(segments[2], body);
    if (method === 'PATCH'  && segments[1] === 'tasks'    && segments[2] && !segments[3])   return updateTask(segments[2], body);
    if (method === 'DELETE' && segments[1] === 'tasks'    && segments[2] && !segments[3])   return deleteTask(segments[2]);
    if (method === 'POST'   && segments[1] === 'tasks'    && segments[3] === 'subtasks')     return addSubtask(segments[2], body);
    if (method === 'PATCH'  && segments[1] === 'subtasks' && segments[2])                    return updateSubtask(segments[2], body);
    if (method === 'DELETE' && segments[1] === 'subtasks' && segments[2])                    return deleteSubtask(segments[2]);
    if (method === 'POST'   && segments[1] === 'tasks'    && segments[3] === 'comments')     return addComment(segments[2], body);
    return err(404, 'Not Found');
  } catch (e) {
    console.error('Handler error:', e);
    return err(500, 'Internal server error');
  }
};
