# SENAI-SP &bull; Portal Corporativo Enterprise & Relatório de Auditoria de Cibersegurança

![SENAI SP Security Hardened](https://img.shields.io/badge/Security-OWASP_Top_10_Hardened-emerald?style=for-the-badge&logo=shield)
![Row Level Security](https://img.shields.io/badge/Database-RLS_Active-blue?style=for-the-badge&logo=postgresql)
![Express & Helmet](https://img.shields.io/badge/Backend-Helmet_CSP_HSTS-darkred?style=for-the-badge&logo=express)

Este repositório contém a versão **Enterprise & Hardened** do Portal **SENAI-SP**, auditada e refatorada sob os mais rigorosos padrões de cibersegurança para aplicações de missão crítica (Zero Trust, OWASP Top 10 e ISO 27001).

---

## 🛡️ Matriz de Auditoria & Conformidade dos 20 Critérios de Segurança

| Nº | Critério de Segurança | Status no Código Legado | Correção e Implementação Enterprise | Arquivos Envolvidos |
|---|---|---|---|---|
| **1** | **Isolamento de Secrets e APIs via `.env`** | ❌ Chave de API no texto inicial | Isolamento completo via `dotenv` e criação de `.env.example`. Nenhuma credencial trafega no código fonte. | [`.env.example`](file:///c:/Users/Aluno/Documents/Stitch/.env.example), [`server.js`](file:///c:/Users/Aluno/Documents/Stitch/server.js) |
| **2** | **Proteção de Segredos no Git** | ❌ Ausência de `.gitignore` | Arquivo `.gitignore` criado protegendo `.env*`, `.pem`, chaves criptográficas e logs. | [`.gitignore`](file:///c:/Users/Aluno/Documents/Stitch/.gitignore) |
| **3** | **Segregação de Chaves Públicas e de Serviço** | ⚠️ Cliente direto sem mediação | Backend seguro implementado em Node/Express para intermediar chamadas de serviço e APIs externas. | [`server.js`](file:///c:/Users/Aluno/Documents/Stitch/server.js) |
| **4** | **Row-Level Security (RLS) no Banco de Dados** | ❌ Inexistente | Esquema PostgreSQL configurado com políticas de RLS onde alunos acessam apenas seus próprios registros (`USING id = current_user_id`). | [`schema.sql`](file:///c:/Users/Aluno/Documents/Stitch/schema.sql) |
| **5** | **Criptografia em Trânsito (TLS) e em Repouso** | ⚠️ HTTP simples sem HSTS | Forçamento de HTTPS em produção, HSTS de 1 ano (`max-age=31536000; preload`) e colunas com `pgp_sym_encrypt` (AES-256). | [`server.js`](file:///c:/Users/Aluno/Documents/Stitch/server.js), [`schema.sql`](file:///c:/Users/Aluno/Documents/Stitch/schema.sql) |
| **6** | **Autenticação e Autorização no Servidor** | ❌ Simulação no front-end | Endpoint seguro `/api/auth/login` com validação de credenciais, emissão de JWT criptografado e controle no backend. | [`server.js`](file:///c:/Users/Aluno/Documents/Stitch/server.js) |
| **7** | **Princípio do Menor Privilégio (Least Privilege)** | ❌ Sem RBAC estruturado | Criação de roles de banco segregadas (`senai_readonly`, `senai_app_user`, `senai_admin`) e CORS restritivo. | [`schema.sql`](file:///c:/Users/Aluno/Documents/Stitch/schema.sql), [`server.js`](file:///c:/Users/Aluno/Documents/Stitch/server.js) |
| **8** | **Impedir Adulteração de Campos Protegidos** | ❌ Cálculo de bolsas no cliente | A lógica de cálculo do Programa de Gratuidade e regras de negócio foram migradas para o endpoint `/api/bolsas/simular`. | [`server.js`](file:///c:/Users/Aluno/Documents/Stitch/server.js) |
| **9** | **Cookies com Flags HttpOnly, Secure e SameSite** | ❌ Ausente | Emissão de cookies com `httpOnly: true`, `secure: true`, `sameSite: 'Strict'` e validade controlada. | [`server.js`](file:///c:/Users/Aluno/Documents/Stitch/server.js) |
| **10** | **Armazenamento de Senhas com Hash Seguro** | ❌ Senhas em texto claro | Modelagem com Bcrypt (salt rounds 12+) e Argon2id para proteção contra vazamentos de credenciais. | [`schema.sql`](file:///c:/Users/Aluno/Documents/Stitch/schema.sql), [`server.js`](file:///c:/Users/Aluno/Documents/Stitch/server.js) |
| **11** | **Rate Limiting Anti-Força Bruta** | ❌ Requisições ilimitadas | `express-rate-limit` configurado com limite global (200 req/15min) e limite rigoroso para login (5 tentativas/15min). | [`server.js`](file:///c:/Users/Aluno/Documents/Stitch/server.js) |
| **12** | **Proteção contra Bots (Honeypot & Captcha)** | ❌ Ausente | Implementação de campo Honeypot invisível (`bot_trap`) nos formulários de autenticação para neutralizar bots automatizados. | [`index.html`](file:///c:/Users/Aluno/Documents/Stitch/index.html), [`server.js`](file:///c:/Users/Aluno/Documents/Stitch/server.js) |
| **13** | **Consultas Parametrizadas (Prepared Statements)** | ❌ Risco de injeção SQL | Documentação e uso exclusivo de prepared statements parametrizados para impedir SQL Injection. | [`schema.sql`](file:///c:/Users/Aluno/Documents/Stitch/schema.sql) |
| **14** | **Validação de Entrada com Esquemas Tipados** | ⚠️ Validação frágil | Sanitização estrita de CPF/RA, tipos numéricos e limites máximos de caracteres no servidor e cliente. | [`server.js`](file:///c:/Users/Aluno/Documents/Stitch/server.js), [`index.html`](file:///c:/Users/Aluno/Documents/Stitch/index.html) |
| **15** | **Escape Rigoroso contra XSS** | ❌ `innerHTML` sem escape | Implementação de função centralizada `escapeHtml()` aplicada a todas as interpolações dinâmicas no DOM. | [`index.html`](file:///c:/Users/Aluno/Documents/Stitch/index.html) |
| **16** | **Restrição Rigorosa de Uploads** | ⚠️ Sem validação | Políticas de upload com limitação de payload (`limit: '50kb'`) e diretrizes de armazenamento seguro. | [`server.js`](file:///c:/Users/Aluno/Documents/Stitch/server.js) |
| **17** | **Zero Over-fetching (Redação de Dados Sensíveis)** | ⚠️ Dados brutos no front | Respostas da API formatadas estritamente com dados públicos/mascarados (`***.1234`), sem expor senhas ou tokens internos. | [`server.js`](file:///c:/Users/Aluno/Documents/Stitch/server.js) |
| **18** | **Cabeçalhos HTTP de Segurança Robustos** | ❌ Ausentes | Helmet configurado com Content Security Policy (CSP), `X-Frame-Options: DENY` (anti-clickjacking) e `X-Content-Type-Options: nosniff`. | [`server.js`](file:///c:/Users/Aluno/Documents/Stitch/server.js), [`index.html`](file:///c:/Users/Aluno/Documents/Stitch/index.html) |
| **19** | **Forçar HTTPS e Redirecionamentos Seguros** | ❌ HTTP | Middleware de redirecionamento obrigatório para HTTPS e HSTS em ambiente de produção. | [`server.js`](file:///c:/Users/Aluno/Documents/Stitch/server.js) |
| **20** | **Segurança de Dependências (Supply Chain)** | ⚠️ CDN sem pin de versão | Fixação de versões específicas de bibliotecas CDN e scripts de auditoria automatizada (`npm audit`). | [`package.json`](file:///c:/Users/Aluno/Documents/Stitch/package.json), [`index.html`](file:///c:/Users/Aluno/Documents/Stitch/index.html) |

---

## 📂 Arquitetura do Projeto Refatorado

```
/
├── .gitignore          # Proteção de credenciais, chaves PEM e arquivos de ambiente
├── .env.example        # Template seguro de variáveis de ambiente
├── package.json        # Dependências auditadas (Helmet, Rate-Limit, Bcrypt, Express)
├── server.js           # Backend corporativo com middlewares de segurança OWASP
├── schema.sql          # Banco de dados PostgreSQL com RLS, criptografia e RBAC
├── index.html          # Front-end blindado contra XSS com CSP e Honeypot anti-bot
└── README.md           # Relatório de auditoria e governança de segurança
```

---

## 🚀 Como Executar o Ambiente Corporativo

1. **Instalar dependências de segurança:**
   ```bash
   npm install
   ```

2. **Configurar as variáveis de ambiente:**
   ```bash
   cp .env.example .env
   # Preencha suas credenciais reais no arquivo .env (nunca compartilhe este arquivo)
   ```

3. **Iniciar o servidor seguro:**
   ```bash
   npm start
   ```
   O portal estará disponível em `http://localhost:3000` com todos os cabeçalhos de segurança, CSP e rate limitings ativados.
