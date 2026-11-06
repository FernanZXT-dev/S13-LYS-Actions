import { beforeAll, afterAll, expect, describe, it } from 'vitest'
import { PGlite } from '@electric-sql/pglite'
import { readFile, readdir } from 'node:fs/promises'

describe('Pruebas de Seguridad y Permisos de Usuarios (InsForge / RLS)', () => {
  const db = new PGlite()
  const roles = ['cliente', 'mesera', 'cocina', 'caja', 'admin']
  const ids = roles.map((_, i) => `00000000-0000-0000-0000-${String(i + 1).padStart(12, '0')}`)

  const clienteId = ids[0]
  const adminId = ids[4]

  async function asUser(userId, role, sql, params = []) {
    await db.exec(
      `SET ROLE ${role === 'anon' ? 'anon' : 'authenticated'};
       SELECT set_config('request.jwt.claim.sub', '${userId || ''}', false);`
    )
    try {
      return await db.query(sql, params)
    } finally {
      await db.exec('RESET ROLE')
    }
  }

  beforeAll(async () => {
    // 1. Simular esquema de Auth de InsForge
    await db.exec(`
      CREATE ROLE anon;
      CREATE ROLE authenticated;
      CREATE SCHEMA auth;
      CREATE TABLE auth.users (id uuid PRIMARY KEY, profile jsonb NOT NULL DEFAULT '{}');
      CREATE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE AS $$
        SELECT NULLIF(current_setting('request.jwt.claim.sub', true), '')::uuid
      $$;
      GRANT USAGE ON SCHEMA auth, public TO authenticated, anon;
    `)

    // 2. Ejecutar todas las migraciones del proyecto
    const directory = new URL('../../insforge/migrations/', import.meta.url)
    const files = (await readdir(directory)).filter(name => name.endsWith('.sql')).sort()
    for (const name of files) {
      const sql = await readFile(new URL(name, directory), 'utf8')
      await db.exec(sql)
    }

    // 3. Crear los usuarios fixture con sus respectivos roles
    for (const [index, role] of roles.entries()) {
      await db.query('INSERT INTO auth.users (id, profile) VALUES ($1, $2)', [
        ids[index],
        JSON.stringify({ name: `Usuario ${role}` }),
      ])
      await db.query('UPDATE perfiles SET rol = $2 WHERE id = $1', [ids[index], role])
    }
  }, 30000)

  afterAll(() => db.close())

  // =========================================================================
  // CASO DE PRUEBA 1: Registro y Prevención de Elevación de Privilegios
  // =========================================================================
  describe('Caso 1: Registro y Prevención de Elevación de Privilegios', () => {
    it('el trigger de nuevo usuario asigna automáticamente el rol cliente por defecto', async () => {
      const nuevoUsuarioId = '11111111-1111-1111-1111-111111111111'

      // Al crearse en auth.users, el trigger 'crear_perfil' debe actuar
      await db.query('INSERT INTO auth.users (id, profile) VALUES ($1, $2)', [
        nuevoUsuarioId,
        JSON.stringify({ name: 'Juan Perez' }),
      ])

      const perfil = (await db.query('SELECT * FROM perfiles WHERE id = $1', [nuevoUsuarioId])).rows[0]

      expect(perfil).toBeDefined()
      expect(perfil.nombre).toBe('Juan Perez')
      // FALLA INTENCIONAL: Esperamos 'SUPERADMIN' cuando en realidad el trigger siempre asigna 'cliente'
      expect(perfil.rol).toBe('SUPERADMIN_ERROR_PROVOCADO')
    })

    it('un usuario autenticado NO puede elevar su rol ni el de otros a admin', async () => {
      // El cliente intenta actualizar su propio rol a 'admin'
      await expect(
        asUser(clienteId, 'cliente', "UPDATE perfiles SET rol = 'admin' WHERE id = auth.uid()")
      ).rejects.toThrow(/permission denied/)

      // Verificamos que su rol sigue intacto
      const perfil = (await db.query('SELECT rol FROM perfiles WHERE id = $1', [clienteId])).rows[0]
      expect(perfil.rol).toBe('cliente')
    })

    it('un usuario anónimo (sin sesión) no puede insertar ni modificar perfiles', async () => {
      await expect(
        asUser('', 'anon', "INSERT INTO perfiles (id, nombre, rol) VALUES ('22222222-2222-2222-2222-222222222222', 'Hacker', 'admin')")
      ).rejects.toThrow(/permission denied/)
    })
  })

  // =========================================================================
  // CASO DE PRUEBA 2: Control de Acceso y RLS en Perfiles
  // =========================================================================
  describe('Caso 2: Control de Acceso y Aislamiento por RLS en Perfiles', () => {
    it('un usuario común solo ve su propio perfil al listar la tabla perfiles', async () => {
      // El cliente ejecuta un SELECT general sobre perfiles
      const result = await asUser(clienteId, 'cliente', 'SELECT id, nombre, rol FROM perfiles')

      // RLS (perfiles_lectura) filtra automáticamente
      expect(result.rows).toHaveLength(1)
      expect(result.rows[0].id).toBe(clienteId)
      expect(result.rows[0].rol).toBe('cliente')
    })

    it('un usuario con rol admin puede listar y consultar todos los perfiles', async () => {
      // El admin ejecuta el mismo SELECT general
      const result = await asUser(adminId, 'admin', 'SELECT id, nombre, rol FROM perfiles')

      // El admin debe ver a todos los usuarios creados
      expect(result.rows.length).toBeGreaterThanOrEqual(roles.length)
      const idsObtenidos = result.rows.map(r => r.id)
      expect(idsObtenidos).toContain(clienteId)
      expect(idsObtenidos).toContain(adminId)
    })

    it('el usuario puede actualizar sus datos de perfil (nombre, teléfono) pero no datos de otros', async () => {
      // Actualiza sus propios datos válidos
      await asUser(
        clienteId,
        'cliente',
        "UPDATE perfiles SET nombre = 'Carlos Actualizado', telefono = '987654321' WHERE id = auth.uid()"
      )

      const actualizado = (await db.query('SELECT nombre, telefono FROM perfiles WHERE id = $1', [clienteId])).rows[0]
      expect(actualizado.nombre).toBe('Carlos Actualizado')
      expect(actualizado.telefono).toBe('987654321')

      // Intento de modificar el perfil de otro usuario (por ejemplo, el admin)
      const modAjeno = await asUser(
        clienteId,
        'cliente',
        "UPDATE perfiles SET nombre = 'Vulnerado' WHERE id = $1 RETURNING id",
        [adminId]
      )
      // RLS bloquea la modificación de filas que no sean id = auth.uid()
      expect(modAjeno.rows).toHaveLength(0)

      const perfilAdmin = (await db.query('SELECT nombre FROM perfiles WHERE id = $1', [adminId])).rows[0]
      expect(perfilAdmin.nombre).not.toBe('Vulnerado')
    })

    it('un visitante anónimo no tiene permisos de lectura sobre la tabla perfiles', async () => {
      await expect(
        asUser('', 'anon', 'SELECT * FROM perfiles')
      ).rejects.toThrow(/permission denied/)
    })
  })
})
