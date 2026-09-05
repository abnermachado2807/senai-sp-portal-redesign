-- ============================================================================
-- SENAI-SP ENTERPRISE DATABASE ARCHITECTURE & SECURITY POLICIES
-- PostgreSQL 15+ com Row-Level Security (RLS) e Princípio do Menor Privilégio
-- ============================================================================

-- 7: Criação de Roles com Menor Privilégio
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'senai_app_user') THEN
    CREATE ROLE senai_app_user WITH LOGIN PASSWORD 'DEFINIR_NO_SECRETS_VAULT';
  END IF;
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'senai_readonly') THEN
    CREATE ROLE senai_readonly WITH LOGIN PASSWORD 'DEFINIR_NO_SECRETS_VAULT';
  END IF;
END $$;

-- 5: Habilitação de Extensões Criptográficas para Criptografia de Dados Sensíveis
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- TABELA 1: ALUNOS (Dados Sensíveis e Hash de Senha)
-- ============================================================================
CREATE TABLE IF NOT EXISTS alunos (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ra VARCHAR(20) UNIQUE NOT NULL,
    cpf_hash VARCHAR(64) NOT NULL, -- 5: CPF armazenado com hash SHA-256 com salt
    cpf_criptografado BYTEA,       -- 5: Criptografia em repouso com AES-256 (pgp_sym_encrypt)
    nome_completo VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    senha_hash VARCHAR(255) NOT NULL, -- 10: Hash Argon2id ou Bcrypt com custo 12+
    perfil VARCHAR(50) DEFAULT 'ALUNO_REGULAR' NOT NULL,
    unidade_id UUID,
    is_ativo BOOLEAN DEFAULT TRUE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- 4: ATIVAÇÃO DE ROW-LEVEL SECURITY (RLS) NA TABELA DE ALUNOS
ALTER TABLE alunos ENABLE ROW LEVEL SECURITY;
ALTER TABLE alunos FORCE ROW LEVEL SECURITY;

-- 4 & 7: POLÍTICA RLS: Alunos só podem ler seu próprio registro
CREATE POLICY aluno_proprio_registro_policy ON alunos
    FOR SELECT
    TO senai_app_user
    USING (id = NULLIF(current_setting('app.current_user_id', true), '')::UUID);

-- 4 & 8: POLÍTICA RLS: Apenas administradores auditados podem atualizar perfis
CREATE POLICY admin_update_alunos_policy ON alunos
    FOR UPDATE
    TO senai_app_user
    USING (current_setting('app.user_role', true) = 'ADMIN')
    WITH CHECK (current_setting('app.user_role', true) = 'ADMIN');

-- ============================================================================
-- TABELA 2: CURSOS E VAGAS DE GRATUIDADE
-- ============================================================================
CREATE TABLE IF NOT EXISTS cursos (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    codigo_curso VARCHAR(50) UNIQUE NOT NULL,
    titulo VARCHAR(255) NOT NULL,
    categoria VARCHAR(50) NOT NULL, -- tecnico, livre, graduacao, ead
    area_tecnologica VARCHAR(100) NOT NULL,
    carga_horaria_horas INT NOT NULL,
    permite_bolsa_pgr BOOLEAN DEFAULT FALSE NOT NULL,
    is_publicado BOOLEAN DEFAULT TRUE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- RLS para Cursos (Leitura Pública de Cursos Publicados)
ALTER TABLE cursos ENABLE ROW LEVEL SECURITY;

CREATE POLICY cursos_leitura_publica ON cursos
    FOR SELECT
    TO senai_readonly, senai_app_user
    USING (is_publicado = TRUE);

-- ============================================================================
-- 13: EXEMPLO DE CONSULTAS PARAMETRIZADAS (PREPARED STATEMENTS)
-- ============================================================================
-- PREPARE buscar_aluno_por_ra (text) AS
--   SELECT id, ra, nome_completo, email, perfil, unidade_id
--   FROM alunos
--   WHERE ra = $1 AND is_ativo = TRUE;

-- EXECUTE buscar_aluno_por_ra('20261234');
