-- Ficha del usuario: datos adicionales para la gestión
ALTER TABLE usuarios
ADD COLUMN IF NOT EXISTS nombre TEXT NULL,
ADD COLUMN IF NOT EXISTS apellido TEXT NULL,
ADD COLUMN IF NOT EXISTS departamento TEXT NULL,
ADD COLUMN IF NOT EXISTS ciudad TEXT NULL,
ADD COLUMN IF NOT EXISTS telefono TEXT NULL;
