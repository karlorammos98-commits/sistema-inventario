const express = require('express');
const { Pool } = require('pg');
const ExcelJS = require('exceljs');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');
const os = require('os');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: 'inventario_local_secret',
    resave: false,
    saveUninitialized: false,
  })
);

const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'inventario_local',
  password: 'admin',
  port: 5432,
});

const publicDir = path.join(__dirname, 'public');

async function ensureRole(nombre) {
  const roleName = String(nombre || '').trim();
  if (!roleName) throw new Error('Nombre de rol inválido');

  const exists = await pool.query(
    'SELECT id FROM roles WHERE LOWER(nombre) = LOWER($1) LIMIT 1',
    [roleName]
  );

  if (exists.rowCount > 0) return exists.rows[0].id;

  const inserted = await pool.query(
    'INSERT INTO roles (nombre) VALUES ($1) RETURNING id',
    [roleName]
  );
  return inserted.rows[0].id;
}

function requireRole(checkFn) {
  return async (req, res, next) => {
    try {
      const usuario = await getUsuarioContext(req);
      if (!usuario) return res.status(401).send('No autenticado');
      if (!checkFn(usuario)) return res.status(403).send('No autorizado');
      req.usuario = usuario;
      return next();
    } catch (err) {
      return res.status(500).send('Error de autorización: ' + err.message);
    }
  };
}

function requireAuthApi(req, res, next) {
  if (req.session && req.session.userId) return next();
  return res.status(401).send('No autenticado');
}

function requireAuthPage(req, res, next) {
  if (req.session && req.session.userId) return next();
  return res.redirect('/login');
}

async function getUsuarioContext(req) {
  const rawId =
    req.session?.userId ||
    req.header('x-usuario-id') ||
    req.query.usuario_id;
  if (!rawId) return null;

  const userId = Number(rawId);
  if (!Number.isInteger(userId) || userId <= 0) return null;

  const result = await pool.query(
    `SELECT
       u.id,
       u.deposito_asignado_id,
       r.nombre AS rol_nombre,
       COALESCE(
         (
           SELECT array_agg(ud.deposito_id)
           FROM usuarios_depositos_permitidos ud
           WHERE ud.usuario_id = u.id
         ),
         ARRAY[]::int[]
       ) AS depositos_permitidos
     FROM usuarios u
     JOIN roles r ON r.id = u.rol_id
     WHERE u.id = $1`,
    [userId]
  );

  if (result.rowCount === 0) return null;

  const rolNombre = (result.rows[0].rol_nombre || '').toLowerCase();
  // Tratamos los roles 'master' y 'god' como super-admin (dios)
  const esMaster = rolNombre === 'master' || rolNombre === 'god';
  const esAdmin = rolNombre === 'admin' || esMaster;
  const esOperador = rolNombre === 'operador';

  return {
    id: result.rows[0].id,
    deposito_asignado_id: result.rows[0].deposito_asignado_id,
    rol_nombre: rolNombre,
    esMaster,
    esAdmin,
    esOperador,
    depositos_permitidos: Array.isArray(result.rows[0].depositos_permitidos)
      ? result.rows[0].depositos_permitidos
      : [],
  };
}

const requireMaster = requireRole((u) => u.esMaster);
const requireAdminOrMaster = requireRole((u) => u.esAdmin || u.esMaster);
const requireOperadorOrAbove = requireRole((u) => u.esMaster || u.esAdmin || u.esOperador);

app.get('/login', (req, res) => {
  res.sendFile(path.join(publicDir, 'login.html'));
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send('Usuario y contraseña son obligatorios');
  }

  try {
    const result = await pool.query(
      `SELECT
         u.id,
         u.username,
         u.password_hash,
         u.deposito_asignado_id,
         r.nombre AS rol_nombre
       FROM usuarios u
       JOIN roles r ON r.id = u.rol_id
       WHERE u.username = $1`,
      [username]
    );

    if (result.rowCount === 0) {
      return res.status(401).send('Credenciales inválidas');
    }

    const user = result.rows[0];
    const stored = user.password_hash || '';
    let ok = false;

    if (stored.startsWith('$2a$') || stored.startsWith('$2b$') || stored.startsWith('$2y$')) {
      ok = await bcrypt.compare(password, stored);
    } else {
      // compatibilidad con registros antiguos sin hash
      ok = password === stored;
    }

    if (!ok) {
      return res.status(401).send('Credenciales inválidas');
    }

    req.session.userId = user.id;

    const acceptsJson = (req.get('accept') || '').includes('application/json');
    if (acceptsJson) {
      return res.json({
        id: user.id,
        username: user.username,
        rol: user.rol_nombre,
        deposito_asignado_id: user.deposito_asignado_id,
      });
    }

    return res.redirect('/');
  } catch (err) {
    return res.status(500).send('Error al iniciar sesión: ' + err.message);
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

app.get('/me', requireAuthApi, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT
         u.id,
         u.username,
         u.deposito_asignado_id,
         r.nombre AS rol_nombre,
         COALESCE(
           (SELECT array_agg(ud.deposito_id) FROM usuarios_depositos_permitidos ud WHERE ud.usuario_id = u.id),
           ARRAY[]::int[]
         ) AS depositos_permitidos
       FROM usuarios u
       JOIN roles r ON r.id = u.rol_id
       WHERE u.id = $1`,
      [req.session.userId]
    );

    if (result.rowCount === 0) {
      return res.status(404).send('Usuario no encontrado');
    }

    const row = result.rows[0];
    const payload = {
      id: row.id,
      username: row.username,
      deposito_asignado_id: row.deposito_asignado_id,
      rol_nombre: row.rol_nombre,
      depositos_permitidos: Array.isArray(row.depositos_permitidos) ? row.depositos_permitidos : [],
    };
    res.json(payload);
  } catch (err) {
    res.status(500).send('Error al obtener usuario: ' + err.message);
  }
});

app.get('/', requireAuthPage, (req, res) => {
  res.sendFile(path.join(publicDir, 'index.html'));
});

app.get('/index.html', requireAuthPage, (req, res) => {
  res.sendFile(path.join(publicDir, 'index.html'));
});

app.use(express.static('public', { index: false }));

app.get('/usuarios', requireAuthApi, async (req, res) => {
  const resdb = await pool.query(
    `SELECT
       u.id,
       u.username,
       u.deposito_asignado_id,
       u.nombre,
       u.apellido,
       u.departamento,
       u.ciudad,
       u.telefono,
       r.nombre AS rol_nombre,
       d.nombre AS deposito_nombre,
       COALESCE(
         (
           SELECT array_agg(ud.deposito_id)
           FROM usuarios_depositos_permitidos ud
           WHERE ud.usuario_id = u.id
         ),
         ARRAY[]::int[]
       ) AS depositos_permitidos
     FROM usuarios u
     JOIN roles r ON r.id = u.rol_id
     LEFT JOIN depositos d ON d.id = u.deposito_asignado_id
     ORDER BY u.username`
  );
  res.json(resdb.rows);
});

// Solo master puede crear usuarios (con ficha)
app.post('/crear-usuario', requireAuthApi, requireMaster, async (req, res) => {
  const {
    username, password, rol_id, deposito_asignado_id,
    nombre, apellido, departamento, ciudad, telefono,
    depositos_permitidos
  } = req.body;
  if (!username || !password || !rol_id) {
    return res.status(400).send('Username, contraseña y rol son obligatorios');
  }
  const pwdStr = String(password);
  if (pwdStr.length < 4) {
    return res.status(400).send('La contraseña debe tener al menos 4 caracteres');
  }
  if (!/^[a-zA-Z0-9]+$/.test(pwdStr)) {
    return res.status(400).send('La contraseña debe ser alfanumérica (solo letras y números)');
  }
  try {
    const passwordHash = await bcrypt.hash(password, 10);
    const insertResult = await pool.query(
      `INSERT INTO usuarios (
        username, password_hash, rol_id, deposito_asignado_id,
        nombre, apellido, departamento, ciudad, telefono
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING id`,
      [
        username, passwordHash, rol_id, deposito_asignado_id || null,
        nombre || null, apellido || null, departamento || null, ciudad || null, telefono || null
      ]
    );

    const newUserId = insertResult.rows[0]?.id;

    // Registrar depósitos permitidos adicionales (además del depósito asignado)
    if (newUserId) {
      let extra = Array.isArray(depositos_permitidos) ? depositos_permitidos : [];
      extra = extra
        .map((d) => Number(d))
        .filter((d) => Number.isInteger(d) && d > 0);

      const depAsignadoNum = deposito_asignado_id ? Number(deposito_asignado_id) : null;
      if (depAsignadoNum && Number.isInteger(depAsignadoNum) && depAsignadoNum > 0 && !extra.includes(depAsignadoNum)) {
        extra.push(depAsignadoNum);
      }

      if (extra.length > 0) {
        await pool.query(
          `INSERT INTO usuarios_depositos_permitidos (usuario_id, deposito_id)
           SELECT $1, unnest($2::int[])
           ON CONFLICT (usuario_id, deposito_id) DO NOTHING`,
          [newUserId, extra]
        );
      }
    }

    res.send('Usuario creado con éxito');
  } catch (err) {
    res.status(500).send('Error al crear usuario: ' + err.message);
  }
});

// Usuario cambia su propia contraseña (requiere contraseña anterior)
app.post('/usuarios/cambiar-password', requireAuthApi, async (req, res) => {
  const userId = req.session?.userId;
  if (!userId) return res.status(401).send('No autenticado');

  const { password_actual, password_nueva } = req.body;
  if (!password_actual || !password_nueva) {
    return res.status(400).send('Contraseña actual y nueva son obligatorias');
  }
  const pwdNueva = String(password_nueva);
  if (pwdNueva.length < 4) {
    return res.status(400).send('La nueva contraseña debe tener al menos 4 caracteres');
  }
  if (!/^[a-zA-Z0-9]+$/.test(pwdNueva)) {
    return res.status(400).send('La nueva contraseña debe ser alfanumérica (solo letras y números)');
  }

  try {
    const r = await pool.query('SELECT password_hash FROM usuarios WHERE id = $1', [userId]);
    if (r.rowCount === 0) return res.status(404).send('Usuario no encontrado');

    const ok = await bcrypt.compare(password_actual, r.rows[0].password_hash);
    if (!ok) return res.status(400).send('Contraseña actual incorrecta');

    const passwordHash = await bcrypt.hash(password_nueva, 10);
    await pool.query('UPDATE usuarios SET password_hash = $1 WHERE id = $2', [passwordHash, userId]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).send('Error al cambiar contraseña: ' + err.message);
  }
});

app.put('/usuarios/:id', requireAuthApi, requireMaster, async (req, res) => {
  const userId = Number(req.params.id);
  if (!Number.isInteger(userId) || userId <= 0) {
    return res.status(400).send('ID de usuario inválido');
  }

  const {
    username, password, rol_id, deposito_asignado_id,
    nombre, apellido, departamento, ciudad, telefono,
    depositos_permitidos
  } = req.body || {};

  try {
    const existing = await pool.query('SELECT id FROM usuarios WHERE id = $1', [userId]);
    if (existing.rowCount === 0) return res.status(404).send('Usuario no encontrado');

    const fields = [];
    const values = [];
    let i = 1;

    if (username !== undefined) {
      const uname = String(username || '').trim();
      if (!uname) return res.status(400).send('Username inválido');
      fields.push(`username = $${i++}`);
      values.push(uname);
    }

    if (password !== undefined) {
      const pwd = String(password || '');
      if (!pwd) return res.status(400).send('Contraseña inválida');
      if (pwd.length < 4) return res.status(400).send('La contraseña debe tener al menos 4 caracteres');
      if (!/^[a-zA-Z0-9]+$/.test(pwd)) return res.status(400).send('La contraseña debe ser alfanumérica (solo letras y números)');
      const passwordHash = await bcrypt.hash(pwd, 10);
      fields.push(`password_hash = $${i++}`);
      values.push(passwordHash);
    }

    if (rol_id !== undefined) {
      const rolIdNum = Number(rol_id);
      if (!Number.isInteger(rolIdNum) || rolIdNum <= 0) return res.status(400).send('rol_id inválido');
      fields.push(`rol_id = $${i++}`);
      values.push(rolIdNum);
    }

    if (deposito_asignado_id !== undefined) {
      const dep = deposito_asignado_id === null || deposito_asignado_id === ''
        ? null
        : Number(deposito_asignado_id);
      if (dep !== null && (!Number.isInteger(dep) || dep <= 0)) {
        return res.status(400).send('deposito_asignado_id inválido');
      }
      fields.push(`deposito_asignado_id = $${i++}`);
      values.push(dep);
    }

    if (nombre !== undefined) { fields.push(`nombre = $${i++}`); values.push(nombre ? String(nombre).trim() : null); }
    if (apellido !== undefined) { fields.push(`apellido = $${i++}`); values.push(apellido ? String(apellido).trim() : null); }
    if (departamento !== undefined) { fields.push(`departamento = $${i++}`); values.push(departamento ? String(departamento).trim() : null); }
    if (ciudad !== undefined) { fields.push(`ciudad = $${i++}`); values.push(ciudad ? String(ciudad).trim() : null); }
    if (telefono !== undefined) { fields.push(`telefono = $${i++}`); values.push(telefono ? String(telefono).trim() : null); }

    if (fields.length === 0 && depositos_permitidos === undefined) {
      return res.status(400).send('Nada para actualizar');
    }

    if (fields.length > 0) {
      values.push(userId);
      await pool.query(`UPDATE usuarios SET ${fields.join(', ')} WHERE id = $${i}`, values);
    }

    // Actualizar depósitos permitidos si vienen en el payload
    if (depositos_permitidos !== undefined) {
      let extra = Array.isArray(depositos_permitidos) ? depositos_permitidos : [];
      extra = extra
        .map((d) => Number(d))
        .filter((d) => Number.isInteger(d) && d > 0);

      // Limpiar y volver a insertar
      await pool.query('DELETE FROM usuarios_depositos_permitidos WHERE usuario_id = $1', [userId]);

      if (extra.length > 0) {
        await pool.query(
          `INSERT INTO usuarios_depositos_permitidos (usuario_id, deposito_id)
           SELECT $1, unnest($2::int[])
           ON CONFLICT (usuario_id, deposito_id) DO NOTHING`,
          [userId, extra]
        );
      }
    }

    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).send('Error al actualizar usuario: ' + err.message);
  }
});

app.delete('/usuarios/:id', requireAuthApi, requireMaster, async (req, res) => {
  const userId = Number(req.params.id);
  if (!Number.isInteger(userId) || userId <= 0) {
    return res.status(400).send('ID de usuario inválido');
  }

  if (req.session?.userId === userId) {
    return res.status(400).send('No puedes eliminar tu propio usuario');
  }

  try {
    const del = await pool.query('DELETE FROM usuarios WHERE id = $1', [userId]);
    if (del.rowCount === 0) return res.status(404).send('Usuario no encontrado');
    return res.status(204).end();
  } catch (err) {
    return res.status(500).send('Error al eliminar usuario: ' + err.message);
  }
});

// Cualquier usuario autenticado puede crear ítems; no-master solo en sus depósitos permitidos
app.post('/items', requireAuthApi, async (req, res) => {
  const { nombre, observacion, categoria_id, deposito_id, cantidad_inicial, es_componentes, detalle_componentes, item_padre_id, componentes } = req.body;

  if (!nombre || !categoria_id || !deposito_id) {
    return res.status(400).send('Nombre, categoría y depósito son obligatorios');
  }

  const cantidadInicial = Math.max(1, Math.floor(Number(cantidad_inicial) || 1));
  const depositoId = Number(deposito_id);
  if (!Number.isInteger(depositoId) || depositoId <= 0) {
    return res.status(400).send('Depósito inválido');
  }

  const usuario = await getUsuarioContext(req);
  if (!usuario) return res.status(401).send('No autenticado');

  if (!usuario.esMaster) {
    let autorizados = Array.isArray(usuario.depositos_permitidos) ? usuario.depositos_permitidos.slice() : [];
    if (autorizados.length === 0 && usuario.deposito_asignado_id) autorizados = [usuario.deposito_asignado_id];
    if (autorizados.length === 0 || !autorizados.includes(depositoId)) {
      return res.status(403).send('No autorizado para crear ítem en ese depósito');
    }
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const catResult = await client.query(
      'SELECT abreviatura FROM categorias WHERE id = $1 FOR UPDATE',
      [categoria_id]
    );

    if (catResult.rowCount === 0) {
      await client.query('ROLLBACK');
      return res.status(400).send('Categoría no encontrada');
    }

    const abreviatura = catResult.rows[0].abreviatura || 'ITEM';

    const seqRes = await client.query(
      'SELECT COALESCE(MAX(secuencia_categoria), 0) + 1 AS first_seq FROM items WHERE categoria_id = $1',
      [categoria_id]
    );
    let nextSeq = Number(seqRes.rows[0].first_seq) || 1;
    const codigosCreados = [];

    const componentesTexto = es_componentes && String(detalle_componentes || '').trim() ? String(detalle_componentes).trim() : null;
    const itemPadreId = item_padre_id ? Number(item_padre_id) : null;
    const parentIdOk = Number.isInteger(itemPadreId) && itemPadreId > 0 ? itemPadreId : null;
    const mainItemIds = [];

    // Una unidad = un ítem con su propio código. Si cantidad es 2, se crean 2 ítems (IMP-0001, IMP-0002).
    for (let i = 0; i < cantidadInicial; i++) {
      const codigo_interno = `${abreviatura}-${String(nextSeq).padStart(4, '0')}`;
      const itemResult = await client.query(
        'INSERT INTO items (nombre, observacion, categoria_id, codigo_interno, secuencia_categoria, componentes, item_padre_id) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id',
        [nombre, observacion || null, categoria_id, codigo_interno, nextSeq, componentesTexto, parentIdOk]
      );
      const itemId = itemResult.rows[0].id;
      mainItemIds.push(itemId);
      await client.query(
        'INSERT INTO existencias (item_id, deposito_id, cantidad) VALUES ($1, $2, 1)',
        [itemId, deposito_id]
      );
      codigosCreados.push(codigo_interno);
      nextSeq++;
    }

    // Crear ítems componente (categoría componentes, vinculados al ítem padre)
    const listaComponentes = Array.isArray(componentes) ? componentes : [];
    if (listaComponentes.length > 0 && mainItemIds.length > 0) {
      const catComp = await client.query(
        "SELECT id, abreviatura FROM categorias WHERE LOWER(nombre) = 'componentes' OR LOWER(abreviatura) = 'comp' LIMIT 1"
      );
      if (catComp.rowCount > 0) {
        const catCompId = catComp.rows[0].id;
        const abrevComp = catComp.rows[0].abreviatura || 'COMP';
        let seqComp = 0;
        const maxSeqRes = await client.query(
          'SELECT COALESCE(MAX(secuencia_categoria), 0) AS m FROM items WHERE categoria_id = $1',
          [catCompId]
        );
        seqComp = Number(maxSeqRes.rows[0]?.m || 0);

        for (const mainId of mainItemIds) {
          for (const comp of listaComponentes) {
            const compNombre = String(comp.nombre || '').trim();
            const compCantidad = Math.max(1, Math.floor(Number(comp.cantidad) || 1));
            if (!compNombre) continue;
            for (let j = 0; j < compCantidad; j++) {
              seqComp++;
              const codComp = `${abrevComp}-${String(seqComp).padStart(4, '0')}`;
              const insComp = await client.query(
                'INSERT INTO items (nombre, categoria_id, codigo_interno, secuencia_categoria, item_padre_id) VALUES ($1, $2, $3, $4, $5) RETURNING id',
                [compNombre, catCompId, codComp, seqComp, mainId]
              );
              await client.query(
                'INSERT INTO existencias (item_id, deposito_id, cantidad) VALUES ($1, $2, 1)',
                [insComp.rows[0].id, deposito_id]
              );
              codigosCreados.push(codComp);
            }
          }
        }
      }
    }

    await client.query('COMMIT');

    res.status(201).json({
      nombre,
      categoria_id,
      deposito_id,
      cantidad_creada: cantidadInicial,
      codigos: codigosCreados,
    });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).send('Error al crear producto: ' + err.message);
  } finally {
    client.release();
  }
});

app.put('/items/:id', requireAuthApi, requireMaster, async (req, res) => {
  const itemId = Number(req.params.id);
  if (!Number.isInteger(itemId) || itemId <= 0) {
    return res.status(400).send('ID de item inválido');
  }

  const { nombre, observacion, categoria_id } = req.body || {};

  try {
    const existing = await pool.query(
      'SELECT id, categoria_id FROM items WHERE id = $1',
      [itemId]
    );
    if (existing.rowCount === 0) return res.status(404).send('Item no encontrado');

    const fields = [];
    const values = [];
    let i = 1;

    if (nombre !== undefined) {
      const n = String(nombre || '').trim();
      if (!n) return res.status(400).send('Nombre inválido');
      fields.push(`nombre = $${i++}`);
      values.push(n);
    }

    if (observacion !== undefined) {
      const obs = String(observacion || '').trim();
      fields.push(`observacion = $${i++}`);
      values.push(obs ? obs : null);
    }

    let newCategoriaId = null;
    if (categoria_id !== undefined) {
      const catIdNum = Number(categoria_id);
      if (!Number.isInteger(catIdNum) || catIdNum <= 0) return res.status(400).send('categoria_id inválido');
      newCategoriaId = catIdNum;
      fields.push(`categoria_id = $${i++}`);
      values.push(catIdNum);
    }

    if (fields.length === 0) return res.status(400).send('Nada para actualizar');

    // Si cambia categoría, recalcular código interno con la abreviatura nueva.
    if (newCategoriaId !== null && newCategoriaId !== Number(existing.rows[0].categoria_id)) {
      const catResult = await pool.query(
        'SELECT abreviatura FROM categorias WHERE id = $1',
        [newCategoriaId]
      );
      if (catResult.rowCount === 0) return res.status(400).send('Categoría no encontrada');
      const abreviatura = catResult.rows[0].abreviatura || 'ITEM';
      const codigoInterno = `${abreviatura}-${itemId}`;
      fields.push(`codigo_interno = $${i++}`);
      values.push(codigoInterno);
    }

    values.push(itemId);
    await pool.query(`UPDATE items SET ${fields.join(', ')} WHERE id = $${i}`, values);

    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).send('Error al actualizar item: ' + err.message);
  }
});

app.delete('/items/:id', requireAuthApi, requireMaster, async (req, res) => {
  const itemId = Number(req.params.id);
  if (!Number.isInteger(itemId) || itemId <= 0) {
    return res.status(400).send('ID de item inválido');
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const existing = await client.query('SELECT id FROM items WHERE id = $1', [itemId]);
    if (existing.rowCount === 0) {
      await client.query('ROLLBACK');
      return res.status(404).send('Item no encontrado');
    }

    await client.query('DELETE FROM movimientos WHERE item_id = $1', [itemId]);
    await client.query('DELETE FROM existencias WHERE item_id = $1', [itemId]);
    await client.query('DELETE FROM items WHERE id = $1', [itemId]);

    await client.query('COMMIT');
    return res.status(204).end();
  } catch (err) {
    await client.query('ROLLBACK');
    return res.status(500).send('Error al eliminar item: ' + err.message);
  } finally {
    client.release();
  }
});

// Solo master puede crear categorías
app.post('/categorias', requireAuthApi, requireMaster, async (req, res) => {
  const { nombre, abreviatura } = req.body;

  if (!nombre || !abreviatura) {
    return res.status(400).send('Nombre y abreviatura son obligatorios');
  }

  try {
    const result = await pool.query(
      'INSERT INTO categorias (nombre, abreviatura) VALUES ($1, $2) RETURNING id, nombre, abreviatura',
      [nombre, abreviatura]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).send('Error al crear categoría: ' + err.message);
  }
});

app.get('/categorias', requireAuthApi, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, nombre, abreviatura FROM categorias ORDER BY nombre'
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).send('Error al obtener categorías: ' + err.message);
  }
});

app.put('/categorias/:id', requireAuthApi, requireMaster, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).send('ID inválido');
  const { nombre, abreviatura } = req.body || {};
  const fields = [];
  const values = [];
  let i = 1;
  if (nombre !== undefined) { fields.push(`nombre = $${i++}`); values.push(String(nombre || '').trim()); }
  if (abreviatura !== undefined) { fields.push(`abreviatura = $${i++}`); values.push(String(abreviatura || '').trim()); }
  if (fields.length === 0) return res.status(400).send('Nada para actualizar');
  values.push(id);
  await pool.query(`UPDATE categorias SET ${fields.join(', ')} WHERE id = $${i}`, values);
  res.json({ ok: true });
});

app.delete('/categorias/:id', requireAuthApi, requireMaster, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).send('ID inválido');
  const used = await pool.query('SELECT COUNT(*)::int AS n FROM items WHERE categoria_id = $1', [id]);
  if (used.rows[0].n > 0) return res.status(409).send('No se puede eliminar: categoría en uso');
  await pool.query('DELETE FROM categorias WHERE id = $1', [id]);
  res.status(204).end();
});

// Solo master puede crear depósitos
app.post('/depositos', requireAuthApi, requireMaster, async (req, res) => {
  const { nombre, ubicacion } = req.body;

  if (!nombre) {
    return res.status(400).send('El nombre del depósito es obligatorio');
  }

  try {
    const result = await pool.query(
      'INSERT INTO depositos (nombre, ubicacion) VALUES ($1, $2) RETURNING id, nombre, ubicacion',
      [nombre, ubicacion || null]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).send('Error al crear depósito: ' + err.message);
  }
});

app.get('/depositos', requireAuthApi, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, nombre, ubicacion FROM depositos ORDER BY nombre'
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).send('Error al obtener depósitos: ' + err.message);
  }
});

app.put('/depositos/:id', requireAuthApi, requireMaster, async (req, res) => {
  const depositoId = Number(req.params.id);
  if (!Number.isInteger(depositoId) || depositoId <= 0) {
    return res.status(400).send('ID de depósito inválido');
  }

  const { nombre, ubicacion } = req.body || {};

  try {
    const existing = await pool.query('SELECT id FROM depositos WHERE id = $1', [depositoId]);
    if (existing.rowCount === 0) return res.status(404).send('Depósito no encontrado');

    const fields = [];
    const values = [];
    let i = 1;

    if (nombre !== undefined) {
      const n = String(nombre || '').trim();
      if (!n) return res.status(400).send('Nombre inválido');
      fields.push(`nombre = $${i++}`);
      values.push(n);
    }

    if (ubicacion !== undefined) {
      const u = String(ubicacion || '').trim();
      fields.push(`ubicacion = $${i++}`);
      values.push(u ? u : null);
    }

    if (fields.length === 0) return res.status(400).send('Nada para actualizar');

    values.push(depositoId);
    await pool.query(`UPDATE depositos SET ${fields.join(', ')} WHERE id = $${i}`, values);

    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).send('Error al actualizar depósito: ' + err.message);
  }
});

app.delete('/depositos/:id', requireAuthApi, requireMaster, async (req, res) => {
  const depositoId = Number(req.params.id);
  if (!Number.isInteger(depositoId) || depositoId <= 0) {
    return res.status(400).send('ID de depósito inválido');
  }

  try {
    const exists = await pool.query('SELECT id FROM depositos WHERE id = $1', [depositoId]);
    if (exists.rowCount === 0) return res.status(404).send('Depósito no encontrado');

    const usedStock = await pool.query(
      'SELECT COUNT(*)::int AS n FROM existencias WHERE deposito_id = $1',
      [depositoId]
    );
    const usedMov = await pool.query(
      'SELECT COUNT(*)::int AS n FROM movimientos WHERE deposito_origen_id = $1 OR deposito_destino_id = $1',
      [depositoId]
    );

    if ((usedStock.rows[0].n || 0) > 0 || (usedMov.rows[0].n || 0) > 0) {
      return res.status(409).send('No se puede eliminar: depósito con existencias o movimientos');
    }

    await pool.query('DELETE FROM depositos WHERE id = $1', [depositoId]);
    return res.status(204).end();
  } catch (err) {
    return res.status(500).send('Error al eliminar depósito: ' + err.message);
  }
});

app.get('/roles', requireAuthApi, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, nombre FROM roles ORDER BY nombre');
    res.json(result.rows);
  } catch (err) {
    res.status(500).send('Error al obtener roles: ' + err.message);
  }
});

app.get('/inventario', requireAuthApi, async (req, res) => {
  try {
    const usuario = await getUsuarioContext(req);

    const params = [];
    let where = '';
    let autorizados = [];

    if (usuario && !usuario.esMaster) {
      autorizados = Array.isArray(usuario.depositos_permitidos)
        ? usuario.depositos_permitidos.slice()
        : [];
      if (autorizados.length === 0 && usuario.deposito_asignado_id) {
        autorizados = [usuario.deposito_asignado_id];
      }
      if (autorizados.length === 0) {
        return res.status(403).send('Usuario sin depósitos autorizados');
      }
    }

    const rawDepositoId = req.query.deposito_id;
    const depositoId = rawDepositoId ? Number(rawDepositoId) : null;
    const filtrarPorDeposito = Number.isInteger(depositoId) && depositoId > 0;

    if (usuario && !usuario.esMaster) {
      if (filtrarPorDeposito && autorizados.includes(depositoId)) {
        where = 'WHERE e.deposito_id = $1';
        params.push(depositoId);
      } else {
        where = 'WHERE e.deposito_id = ANY($1)';
        params.push(autorizados);
      }
    } else {
      if (filtrarPorDeposito) {
        where = 'WHERE e.deposito_id = $1';
        params.push(depositoId);
      }
    }

    const result = await pool.query(
      `SELECT
         i.id AS item_id,
         i.nombre AS item_nombre,
         i.codigo_interno,
         i.componentes,
         d.id AS deposito_id,
         d.nombre AS deposito_nombre,
         e.cantidad
       FROM items i
       JOIN existencias e ON e.item_id = i.id
       JOIN depositos d ON d.id = e.deposito_id
       ${where}
       ORDER BY i.id, d.id`
      ,
      params
    );

    res.json(result.rows);
  } catch (err) {
    res.status(500).send('Error al obtener inventario: ' + err.message);
  }
});

app.get('/item-info', requireAuthApi, async (req, res) => {
  const codigo = String(req.query.codigo || '').trim();
  if (!codigo) return res.status(400).send('Parámetro codigo obligatorio');
  try {
    const r = await pool.query(
      `SELECT i.id, i.nombre, i.codigo_interno, i.item_padre_id, p.nombre AS item_padre_nombre
       FROM items i
       LEFT JOIN items p ON p.id = i.item_padre_id
       WHERE i.codigo_interno = $1 LIMIT 1`,
      [codigo]
    );
    if (r.rowCount === 0) return res.status(404).send('Ítem no encontrado');
    res.json(r.rows[0]);
  } catch (err) {
    res.status(500).send('Error al obtener ítem: ' + err.message);
  }
});

app.get('/items', requireAuthApi, async (req, res) => {
  try {
    const itemPadreId = req.query.item_padre_id ? Number(req.query.item_padre_id) : null;
    const soloComponentes = req.query.solo_componentes === '1' || req.query.solo_componentes === 'true';
    let where = '';
    const params = [];
    if (itemPadreId && Number.isInteger(itemPadreId) && itemPadreId > 0) {
      where = 'WHERE item_padre_id = $1';
      params.push(itemPadreId);
    } else if (soloComponentes) {
      where = 'WHERE item_padre_id IS NOT NULL';
    }
    const result = await pool.query(
      `SELECT id, nombre, codigo_interno, observacion, categoria_id, item_padre_id
       FROM items
       ${where}
       ORDER BY nombre`,
      params
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).send('Error al obtener items: ' + err.message);
  }
});

// Cargar inventario ítem por ítem en un depósito (admin/operador solo en sus depósitos permitidos)
app.post('/inventario-cargar', requireAuthApi, requireOperadorOrAbove, async (req, res) => {
  const { deposito_id, item_codigo, cantidad } = req.body;
  const depositoId = Number(deposito_id);
  const cantidadNum = Number(cantidad);
  const codigo = String(item_codigo || '').trim();

  if (!depositoId || depositoId <= 0 || !codigo || !cantidadNum || cantidadNum <= 0) {
    return res.status(400).send('deposito_id, item_codigo y cantidad (positiva) son obligatorios');
  }

  const usuario = await getUsuarioContext(req);
  if (!usuario) return res.status(401).send('No autenticado');

  if (!usuario.esMaster) {
    let autorizados = Array.isArray(usuario.depositos_permitidos) ? usuario.depositos_permitidos.slice() : [];
    if (autorizados.length === 0 && usuario.deposito_asignado_id) autorizados = [usuario.deposito_asignado_id];
    if (autorizados.length === 0 || !autorizados.includes(depositoId)) {
      return res.status(403).send('No autorizado para cargar inventario en ese depósito');
    }
  }

  try {
    const itemRes = await pool.query('SELECT id FROM items WHERE codigo_interno = $1', [codigo]);
    if (itemRes.rowCount === 0) return res.status(404).send('Ítem no encontrado con ese código');

    const itemId = itemRes.rows[0].id;
    const existRes = await pool.query(
      'SELECT cantidad FROM existencias WHERE item_id = $1 AND deposito_id = $2',
      [itemId, depositoId]
    );

    if (existRes.rowCount > 0) {
      await pool.query(
        'UPDATE existencias SET cantidad = cantidad + $1 WHERE item_id = $2 AND deposito_id = $3',
        [cantidadNum, itemId, depositoId]
      );
    } else {
      await pool.query(
        'INSERT INTO existencias (item_id, deposito_id, cantidad) VALUES ($1, $2, $3)',
        [itemId, depositoId, cantidadNum]
      );
    }
    res.status(201).json({ ok: true, message: 'Inventario cargado' });
  } catch (err) {
    res.status(500).send('Error al cargar inventario: ' + err.message);
  }
});

// Admin, master y operador pueden registrar movimientos (restringido por depósitos autorizados)
app.post('/movimientos', requireAuthApi, requireOperadorOrAbove, async (req, res) => {
  const { item_id, item_codigo, deposito_origen_id, deposito_destino_id, cantidad, observacion } = req.body;

  const cantidadNum = Number(cantidad);
  if (!deposito_origen_id || !deposito_destino_id || !cantidadNum || cantidadNum <= 0) {
    return res
      .status(400)
      .send('Depósitos y cantidad (> 0) son obligatorios');
  }

  let finalItemId = item_id ? Number(item_id) : null;

  try {
    if (!finalItemId) {
      const codigo = String(item_codigo || '').trim();
      if (!codigo) {
        return res.status(400).send('Código de item obligatorio');
      }

      const lookup = await pool.query(
        'SELECT id FROM items WHERE codigo_interno = $1',
        [codigo]
      );
      if (lookup.rowCount === 0) {
        return res.status(404).send('Item no encontrado para el código indicado');
      }
      finalItemId = lookup.rows[0].id;
    }
  } catch (err) {
    return res.status(500).send('Error al validar código de item: ' + err.message);
  }

  const usuario = await getUsuarioContext(req);

  // Solo master puede mover entre cualquier depósito;
  // admin debe tener permisos explícitos sobre ambos depósitos
  if (!usuario) {
    return res.status(401).send('No autenticado');
  }

  // Admin/operador: solo pueden mover DESDE sus depósitos autorizados; el destino puede ser cualquier depósito
  if (!usuario.esMaster) {
    const depOrigen = Number(deposito_origen_id);

    let autorizados = Array.isArray(usuario.depositos_permitidos)
      ? usuario.depositos_permitidos.slice()
      : [];

    if (autorizados.length === 0 && usuario.deposito_asignado_id) {
      autorizados = [usuario.deposito_asignado_id];
    }

    if (autorizados.length === 0 || !autorizados.includes(depOrigen)) {
      return res.status(403).send('No autorizado para mover stock desde ese depósito de origen');
    }
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const origenRes = await client.query(
      'SELECT cantidad FROM existencias WHERE item_id = $1 AND deposito_id = $2 FOR UPDATE',
      [finalItemId, deposito_origen_id]
    );

    if (origenRes.rowCount === 0) {
      await client.query(
        'INSERT INTO existencias (item_id, deposito_id, cantidad) VALUES ($1, $2, $3)',
        [finalItemId, deposito_origen_id, 0]
      );
    }

    const origenRes2 = await client.query(
      'SELECT cantidad FROM existencias WHERE item_id = $1 AND deposito_id = $2 FOR UPDATE',
      [finalItemId, deposito_origen_id]
    );

    const stockActual = Number(origenRes2.rows[0].cantidad) || 0;
    if (stockActual < cantidadNum) {
      await client.query('ROLLBACK');
      return res.status(400).send('Stock insuficiente en el depósito de origen');
    }

    const destinoRes = await client.query(
      'SELECT cantidad FROM existencias WHERE item_id = $1 AND deposito_id = $2 FOR UPDATE',
      [finalItemId, deposito_destino_id]
    );

    if (destinoRes.rowCount === 0) {
      await client.query(
        'INSERT INTO existencias (item_id, deposito_id, cantidad) VALUES ($1, $2, $3)',
        [finalItemId, deposito_destino_id, 0]
      );
    }

    await client.query(
      'UPDATE existencias SET cantidad = cantidad - $1 WHERE item_id = $2 AND deposito_id = $3',
      [cantidadNum, finalItemId, deposito_origen_id]
    );

    await client.query(
      'UPDATE existencias SET cantidad = cantidad + $1 WHERE item_id = $2 AND deposito_id = $3',
      [cantidadNum, finalItemId, deposito_destino_id]
    );

    await client.query(
      `INSERT INTO movimientos (item_id, deposito_origen_id, deposito_destino_id, cantidad, observacion, usuario_id)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [finalItemId, deposito_origen_id, deposito_destino_id, cantidadNum, observacion || null, usuario.id]
    );

    await client.query('COMMIT');

    res.status(201).send('Movimiento registrado con éxito');
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).send('Error al registrar movimiento: ' + err.message);
  } finally {
    client.release();
  }
});

// Historial de movimientos: todos los usuarios ven todos los movimientos (con filtros opcionales)
app.get('/movimientos-historial', requireAuthApi, requireOperadorOrAbove, async (req, res) => {
  try {
    const codigo = String(req.query.codigo || '').trim();
    const usuarioFiltro = String(req.query.usuario || '').trim();
    const fechaDesde = String(req.query.fecha_desde || '').trim();
    const fechaHasta = String(req.query.fecha_hasta || '').trim();

    const conditions = [];
    const params = [];
    let idx = 1;

    if (codigo) {
      conditions.push(`(i.codigo_interno ILIKE $${idx} OR i.nombre ILIKE $${idx})`);
      params.push('%' + codigo + '%');
      idx++;
    }
    if (usuarioFiltro) {
      conditions.push(`(u.username ILIKE $${idx} OR u.nombre ILIKE $${idx} OR u.apellido ILIKE $${idx})`);
      params.push('%' + usuarioFiltro + '%');
      idx++;
    }
    if (fechaDesde) {
      conditions.push(`m.created_at::date >= $${idx}`);
      params.push(fechaDesde);
      idx++;
    }
    if (fechaHasta) {
      conditions.push(`m.created_at::date <= $${idx}`);
      params.push(fechaHasta);
      idx++;
    }

    const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';

    const result = await pool.query(
      `SELECT
         m.id,
         m.cantidad,
         m.observacion,
         m.created_at,
         m.item_id,
         i.nombre AS item_nombre,
         i.codigo_interno,
         i.observacion AS item_observacion,
         m.deposito_origen_id,
         d1.nombre AS deposito_origen_nombre,
         m.deposito_destino_id,
         d2.nombre AS deposito_destino_nombre,
         m.usuario_id,
         u.username AS usuario_username
       FROM movimientos m
       JOIN items i ON i.id = m.item_id
       JOIN depositos d1 ON d1.id = m.deposito_origen_id
       JOIN depositos d2 ON d2.id = m.deposito_destino_id
       LEFT JOIN usuarios u ON u.id = m.usuario_id
       ${where}
       ORDER BY m.id DESC
       LIMIT 500`,
      params
    );

    return res.json(result.rows);
  } catch (err) {
    return res.status(500).send('Error al obtener historial de movimientos: ' + err.message);
  }
});

// Master: ver TODOS los movimientos (sin filtrar por depósito)
app.get('/movimientos-historial-todos', requireAuthApi, requireMaster, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT
         m.id, m.cantidad, m.observacion, m.created_at, m.item_id,
         i.nombre AS item_nombre, i.codigo_interno, i.observacion AS item_observacion,
         m.deposito_origen_id, d1.nombre AS deposito_origen_nombre,
         m.deposito_destino_id, d2.nombre AS deposito_destino_nombre,
         m.usuario_id, u.username AS usuario_username
       FROM movimientos m
       JOIN items i ON i.id = m.item_id
       JOIN depositos d1 ON d1.id = m.deposito_origen_id
       JOIN depositos d2 ON d2.id = m.deposito_destino_id
       LEFT JOIN usuarios u ON u.id = m.usuario_id
       ORDER BY m.id DESC
       LIMIT 500`
    );
    return res.json(result.rows);
  } catch (err) {
    return res.status(500).send('Error al obtener historial: ' + err.message);
  }
});

// Movimientos de un ítem por su código (para buscar items)
app.get('/movimientos-por-item', requireAuthApi, async (req, res) => {
  const codigo = String(req.query.codigo || '').trim();
  if (!codigo) return res.status(400).send('Parámetro codigo obligatorio');

  try {
    const result = await pool.query(
      `SELECT
         m.id, m.cantidad, m.observacion, m.created_at, m.item_id,
         i.nombre AS item_nombre, i.codigo_interno,
         m.deposito_origen_id, d1.nombre AS deposito_origen_nombre,
         m.deposito_destino_id, d2.nombre AS deposito_destino_nombre,
         m.usuario_id, u.username AS usuario_username
       FROM movimientos m
       JOIN items i ON i.id = m.item_id
       JOIN depositos d1 ON d1.id = m.deposito_origen_id
       JOIN depositos d2 ON d2.id = m.deposito_destino_id
       LEFT JOIN usuarios u ON u.id = m.usuario_id
       WHERE i.codigo_interno = $1
       ORDER BY m.id DESC`,
      [codigo]
    );
    return res.json(result.rows);
  } catch (err) {
    return res.status(500).send('Error al obtener movimientos del ítem: ' + err.message);
  }
});

app.get('/exportar-excel', requireAuthApi, async (req, res) => {
  try {
    const usuario = await getUsuarioContext(req);

    const params = [];
    let where = '';

    // master ve todo (opcionalmente filtrado por query);
    // admin/operador solo ven los depósitos autorizados
    if (usuario && !usuario.esMaster) {
      let autorizados = Array.isArray(usuario.depositos_permitidos)
        ? usuario.depositos_permitidos.slice()
        : [];

      // compatibilidad: si no hay tabla de permisos pero sí depósito asignado, usarlo
      if (autorizados.length === 0 && usuario.deposito_asignado_id) {
        autorizados = [usuario.deposito_asignado_id];
      }

      if (autorizados.length === 0) {
        return res.status(403).send('Usuario sin depósitos autorizados');
      }

      where = 'WHERE e.deposito_id = ANY($1)';
      params.push(autorizados);
    } else {
      const rawDepositoId = req.query.deposito_id;
      if (rawDepositoId) {
        const depositoId = Number(rawDepositoId);
        if (Number.isInteger(depositoId) && depositoId > 0) {
          where = 'WHERE e.deposito_id = $1';
          params.push(depositoId);
        }
      }
    }

    const result = await pool.query(
      `SELECT
         i.codigo_interno,
         i.nombre AS item_nombre,
         c.nombre AS categoria_nombre,
         d.nombre AS deposito_nombre,
         e.cantidad,
         i.componentes
       FROM items i
       LEFT JOIN categorias c ON c.id = i.categoria_id
       JOIN existencias e ON e.item_id = i.id
       JOIN depositos d ON d.id = e.deposito_id
       ${where}
       ORDER BY c.nombre, i.nombre, d.nombre`
      ,
      params
    );

    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('Inventario');

    worksheet.columns = [
      { header: 'Código interno', key: 'codigo_interno', width: 20 },
      { header: 'Producto', key: 'item_nombre', width: 30 },
      { header: 'Categoría', key: 'categoria_nombre', width: 20 },
      { header: 'Depósito', key: 'deposito_nombre', width: 25 },
      { header: 'Cantidad', key: 'cantidad', width: 12 },
      { header: 'Componentes', key: 'componentes', width: 40 },
    ];

    result.rows.forEach((row) => {
      worksheet.addRow(row);
    });

    worksheet.getRow(1).font = { bold: true };

    res.setHeader(
      'Content-Type',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    );
    res.setHeader(
      'Content-Disposition',
      'attachment; filename=\"inventario.xlsx\"'
    );

    await workbook.xlsx.write(res);
    res.end();
  } catch (err) {
    res.status(500).send('Error al exportar Excel: ' + err.message);
  }
});

function setExcelHeaders(res, filename) {
  res.setHeader(
    'Content-Type',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
  );
  res.setHeader('Content-Disposition', `attachment; filename=\"${filename}\"`);
}

async function sendExcel(res, filename, sheetName, columns, rows) {
  const workbook = new ExcelJS.Workbook();
  const worksheet = workbook.addWorksheet(sheetName);
  worksheet.columns = columns;
  rows.forEach((row) => worksheet.addRow(row));
  worksheet.getRow(1).font = { bold: true };

  setExcelHeaders(res, filename);
  await workbook.xlsx.write(res);
  res.end();
}

app.get('/exportar-usuarios-excel', requireAuthApi, requireMaster, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT
         u.id,
         u.username,
         r.nombre AS rol,
         d.nombre AS deposito,
         d.ubicacion
       FROM usuarios u
       JOIN roles r ON r.id = u.rol_id
       LEFT JOIN depositos d ON d.id = u.deposito_asignado_id
       ORDER BY u.username`
    );

    await sendExcel(
      res,
      'usuarios.xlsx',
      'Usuarios',
      [
        { header: 'ID', key: 'id', width: 8 },
        { header: 'Usuario', key: 'username', width: 22 },
        { header: 'Rol', key: 'rol', width: 14 },
        { header: 'Depósito', key: 'deposito', width: 22 },
        { header: 'Ubicación', key: 'ubicacion', width: 24 },
      ],
      result.rows
    );
  } catch (err) {
    return res.status(500).send('Error al exportar usuarios: ' + err.message);
  }
});

app.get('/exportar-items-excel', requireAuthApi, requireMaster, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT
         i.id,
         i.codigo_interno,
         i.nombre,
         c.nombre AS categoria,
         c.abreviatura
       FROM items i
       LEFT JOIN categorias c ON c.id = i.categoria_id
       ORDER BY i.nombre`
    );

    await sendExcel(
      res,
      'items.xlsx',
      'Items',
      [
        { header: 'ID', key: 'id', width: 8 },
        { header: 'Código', key: 'codigo_interno', width: 18 },
        { header: 'Nombre', key: 'nombre', width: 30 },
        { header: 'Categoría', key: 'categoria', width: 22 },
        { header: 'Abrev.', key: 'abreviatura', width: 12 },
      ],
      result.rows
    );
  } catch (err) {
    return res.status(500).send('Error al exportar items: ' + err.message);
  }
});

app.get('/exportar-depositos-excel', requireAuthApi, requireMaster, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, nombre, ubicacion FROM depositos ORDER BY nombre'
    );

    await sendExcel(
      res,
      'depositos.xlsx',
      'Depósitos',
      [
        { header: 'ID', key: 'id', width: 8 },
        { header: 'Nombre', key: 'nombre', width: 26 },
        { header: 'Ubicación', key: 'ubicacion', width: 28 },
      ],
      result.rows
    );
  } catch (err) {
    return res.status(500).send('Error al exportar depósitos: ' + err.message);
  }
});

async function ensureMovimientosCreatedAt() {
  try {
    await pool.query(
      'ALTER TABLE movimientos ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP'
    );
  } catch (err) {
    console.warn('Movimientos created_at (opcional):', err.message);
  }
}

async function ensureItemsComponentes() {
  try {
    await pool.query(
      'ALTER TABLE items ADD COLUMN IF NOT EXISTS componentes TEXT'
    );
    await pool.query(
      'ALTER TABLE items ADD COLUMN IF NOT EXISTS item_padre_id INTEGER REFERENCES items(id)'
    );
  } catch (err) {
    console.warn('Items componentes (opcional):', err.message);
  }
}

async function ensureCategoriaComponentes() {
  try {
    const r = await pool.query(
      "SELECT id FROM categorias WHERE LOWER(nombre) = 'componentes' OR LOWER(abreviatura) = 'comp' LIMIT 1"
    );
    if (r.rowCount === 0) {
      await pool.query(
        "INSERT INTO categorias (nombre, abreviatura) VALUES ('COMPONENTES', 'COMP')"
      );
    }
  } catch (err) {
    console.warn('Categoría componentes (opcional):', err.message);
  }
}

/**
 * Migración única: ítems con cantidad > 1 en existencias se dividen en varios ítems
 * (1 ítem por unidad), cada uno con su código único. Así en "Ver stock" salen N códigos.
 */
async function splitExistenciasEnUnidades() {
  const client = await pool.connect();
  try {
    const res = await client.query(
      `SELECT e.item_id, e.deposito_id, e.cantidad, i.nombre, i.observacion, i.categoria_id
       FROM existencias e
       JOIN items i ON i.id = e.item_id
       WHERE e.cantidad > 1`
    );
    if (res.rows.length === 0) return;

    for (const row of res.rows) {
      const { item_id, deposito_id, cantidad, nombre, observacion, categoria_id } = row;
      const nuevos = cantidad - 1;

      await client.query('BEGIN');
      try {
        const cat = await client.query('SELECT abreviatura FROM categorias WHERE id = $1 FOR UPDATE', [categoria_id]);
        if (cat.rowCount === 0) {
          await client.query('ROLLBACK');
          continue;
        }
        const abreviatura = cat.rows[0].abreviatura || 'ITEM';
        const seqRes = await client.query(
          'SELECT COALESCE(MAX(secuencia_categoria), 0) + 1 AS first_seq FROM items WHERE categoria_id = $1',
          [categoria_id]
        );
        let nextSeq = Number(seqRes.rows[0].first_seq) || 1;

        for (let i = 0; i < nuevos; i++) {
          const codigo_interno = `${abreviatura}-${String(nextSeq).padStart(4, '0')}`;
          const ins = await client.query(
            'INSERT INTO items (nombre, observacion, categoria_id, codigo_interno, secuencia_categoria) VALUES ($1, $2, $3, $4, $5) RETURNING id',
            [nombre, observacion || null, categoria_id, codigo_interno, nextSeq]
          );
          await client.query(
            'INSERT INTO existencias (item_id, deposito_id, cantidad) VALUES ($1, $2, 1)',
            [ins.rows[0].id, deposito_id]
          );
          nextSeq++;
        }
        await client.query(
          'UPDATE existencias SET cantidad = 1 WHERE item_id = $1 AND deposito_id = $2',
          [item_id, deposito_id]
        );
        await client.query('COMMIT');
      } catch (err) {
        await client.query('ROLLBACK');
        console.warn('Split existencias:', err.message);
      }
    }
  } catch (err) {
    console.warn('splitExistenciasEnUnidades:', err.message);
  } finally {
    client.release();
  }
}

function getLocalIPs() {
  const ifaces = os.networkInterfaces();
  const ips = [];
  for (const name of Object.keys(ifaces)) {
    for (const iface of ifaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) ips.push(iface.address);
    }
  }
  return ips;
}

async function start() {
  await ensureRole('master');
  await ensureMovimientosCreatedAt();
  await ensureItemsComponentes();
  await ensureCategoriaComponentes();
  await splitExistenciasEnUnidades();
  const port = 3000;
  app.listen(port, '0.0.0.0', () => {
    console.log('Servidor en http://localhost:' + port);
    const ips = getLocalIPs();
    if (ips.length > 0) {
      console.log('En tu red local, abre desde otro dispositivo:');
      ips.forEach(ip => console.log('  http://' + ip + ':' + port));
    }
  });
}

start().catch((err) => {
  console.error('Error al iniciar servidor:', err);
  process.exit(1);
});