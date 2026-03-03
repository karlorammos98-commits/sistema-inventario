-- Añade fecha/hora de creación a movimientos (para listados con formato DD-MM-AAAA).
ALTER TABLE movimientos
  ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;
