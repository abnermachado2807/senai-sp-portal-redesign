/**
 * ============================================================================
 * SENAI-SP ENTERPRISE APPLICATION SERVER
 * Padrões de Segurança: OWASP Top 10, Zero Trust, Defense-in-Depth
 * ============================================================================
 */

import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

// 1 & 2: Carregamento seguro de variáveis de ambiente
dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';

// 19: Forçar HTTPS e Proxy Seguro em ambiente de produção
if (IS_PROD) {
  app.set('trust proxy', 1);
  app.use((req, res, next) => {
    if (req.headers['x-forwarded-proto'] !== 'https') {
      return res.redirect(301, `https://${req.headers.host}${req.url}`);
    }
    next();
  });
}

// 18: Cabeçalhos HTTP de Segurança Avançados via Helmet
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
          "'self'",
          "'unsafe-inline'", // Permitido com controle para scripts inline do design system
          'https://cdn.tailwindcss.com',
          'https://unpkg.com'
        ],
        styleSrc: [
          "'self'",
          "'unsafe-inline'",
          'https://fonts.googleapis.com'
        ],
        fontSrc: [
          "'self'",
          'https://fonts.gstatic.com'
        ],
        imgSrc: ["'self'", 'data:', 'https://images.unsplash.com', 'https://img.shields.io'],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"], // Previne Clickjacking (X-Frame-Options: DENY)
        upgradeInsecureRequests: IS_PROD ? [] : null
      }
    },
    crossOriginEmbedderPolicy: false,
    hsts: {
      maxAge: 31536000, // 1 ano (HSTS)
      includeSubDomains: true,
      preload: true
    },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
  })
);

// Configuração de CORS Estrita (Menor Privilégio)
const allowedOrigins = [process.env.APP_URL || 'http://localhost:3000'];
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error('Origem não autorizada pela política CORS'));
      }
    },
    credentials: true,
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
  })
);

// 9: Cookies Seguros e Parsing de JSON com limites de payload
app.use(cookieParser(process.env.COOKIE_SECRET || 'senai_sp_secure_cookie_secret_2026'));
app.use(express.json({ limit: '50kb' })); // Previne ataques de negação de serviço por payloads gigantes
app.use(express.urlencoded({ extended: false, limit: '50kb' }));

// 11: Rate Limiting Global
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: 429,
    error: 'Muitas requisições originadas deste IP. Tente novamente em 15 minutos.'
  }
});
app.use('/api/', globalLimiter);

// 11 & 12: Rate Limiting Específico para Autenticação (Anti Força Bruta e Anti Bot)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // Apenas 5 tentativas consecutivas de login
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: 429,
    error: 'Limite de tentativas de acesso excedido. Por favor, aguarde 15 minutos antes de tentar novamente.'
  }
});

// Arquivos Estáticos com Headers de Cache Seguros
app.use(
  express.static(__dirname, {
    dotfiles: 'ignore', // 1: Nunca servir arquivos ocultos como .env ou .git
    etag: true,
    lastModified: true,
    maxAge: IS_PROD ? '1d' : '0'
  })
);

/**
 * ============================================================================
 * UTILITÁRIOS DE SEGURANÇA (Validação, Sanitização e Hash)
 * ============================================================================
 */

// 15: Sanitização contra XSS
function sanitizeHtml(input) {
  if (typeof input !== 'string') return '';
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}

// 14: Validador de Formato de CPF e RA
function isValidUserIdentifier(id) {
  if (typeof id !== 'string') return false;
  const cleanId = id.replace(/[\.\-\s]/g, '');
  // Aceita RA numérico (4 a 12 dígitos) ou CPF (11 dígitos)
  return /^\d{4,12}$/.test(cleanId);
}

/**
 * ============================================================================
 * ENDPOINTS SEGUROS DA API
 * ============================================================================
 */

// 6, 8, 9, 10, 11, 12, 14, 15, 17: Rota de Autenticação Segura do Portal do Aluno
app.post('/api/auth/login', authLimiter, (req, res) => {
  try {
    const { identifier, password, bot_trap } = req.body;

    // 12: Proteção contra Bots (Honeypot Validation)
    if (bot_trap && bot_trap.trim().length > 0) {
      // Se o campo oculto honeypot foi preenchido, é um bot malicioso.
      // Retorna 200 falso ou erro para não instruir o bot.
      return res.status(400).json({ error: 'Falha na validação de segurança.' });
    }

    // 14 & 15: Validação de Entrada Estrita
    if (!identifier || !isValidUserIdentifier(identifier)) {
      return res.status(400).json({ error: 'Identificador (CPF ou RA) inválido.' });
    }

    if (!password || typeof password !== 'string' || password.length < 6 || password.length > 64) {
      return res.status(400).json({ error: 'Credenciais inválidas.' });
    }

    // 13: Simulação de Consulta Parametrizada segura no Banco de Dados:
    // Ex: SELECT id, nome, role, senha_hash FROM alunos WHERE documento = $1;
    const sanitizedId = sanitizeHtml(identifier.trim());

    // 9: Emissão de Cookie de Sessão com Flags Obrigatórias de Segurança
    res.cookie('senai_session', 'token_jwt_assinado_criptografado', {
      httpOnly: true, // 9: Inacessível via JavaScript do navegador (Previne roubo via XSS)
      secure: IS_PROD, // 9: Apenas transmitido sob HTTPS em produção
      sameSite: 'Strict', // 9: Proteção contra CSRF
      maxAge: 3600000, // 1 hora
      path: '/'
    });

    // 17: Retornar estritamente o necessário (Nunca retornar hashes de senha ou dados sensíveis)
    return res.status(200).json({
      success: true,
      message: 'Autenticação realizada com sucesso no Portal do Aluno.',
      user: {
        idMasked: `***.${sanitizedId.slice(-4)}`,
        perfil: 'Aluno Regular'
      }
    });

  } catch (error) {
    // Tratamento de erro sem expor detalhes internos do servidor
    console.error('[AUTH_ERROR]', error.message);
    return res.status(500).json({ error: 'Erro interno no processamento de autenticação.' });
  }
});

// 8, 14, 17: Endpoint Seguro de Simulação de Bolsa 100% (Validação no Servidor)
app.post('/api/bolsas/simular', (req, res) => {
  try {
    const { rendaTotal, numeroMembros } = req.body;

    const renda = Number(rendaTotal);
    const membros = Number(numeroMembros);

    // Validação estrita de tipos
    if (isNaN(renda) || renda < 0 || isNaN(membros) || membros < 1 || membros > 30) {
      return res.status(400).json({ error: 'Parâmetros de renda ou número de membros inválidos.' });
    }

    const SALARIO_MINIMO_NACIONAL = 1412.00;
    const TETO_PER_CAPITA = 1.5 * SALARIO_MINIMO_NACIONAL; // R$ 2.118,00
    const rendaPerCapita = renda / membros;

    // 8: Imutabilidade - O cálculo e a decisão de elegibilidade ocorrem exclusivamente no backend
    const isElegivel = rendaPerCapita <= TETO_PER_CAPITA;

    return res.status(200).json({
      success: true,
      elegivel: isElegivel,
      rendaPerCapitaCalculada: Number(rendaPerCapita.toFixed(2)),
      tetoRegimental: TETO_PER_CAPITA,
      mensagem: isElegivel 
        ? 'Critério de gratuidade atendido conforme o Programa de Gratuidade Regimental do SENAI-SP.' 
        : 'Renda per capita calculada acima do limite de gratuidade regimental.'
    });

  } catch (error) {
    return res.status(500).json({ error: 'Erro ao processar cálculo de elegibilidade.' });
  }
});

// Middleware Global de Tratamento de Erros (Sem vazamento de Stack Traces)
app.use((err, req, res, next) => {
  console.error('[UNHANDLED_ERROR]', err.message);
  res.status(err.status || 500).json({
    error: 'Ocorreu um erro no processamento da solicitação.'
  });
});

// Iniciar Servidor
app.listen(PORT, () => {
  console.log(`[SENAI-SP ENTERPRISE SERVER] Ativo em http://localhost:${PORT}`);
  console.log(`[SECURITY] Headers Helmet, CSP, HSTS e Rate Limiting ativados.`);
});
