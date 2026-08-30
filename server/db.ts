import { DatabaseSync } from "node:sqlite";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

// Ensure data directory exists
const DATA_DIR = path.join(process.cwd(), "data");
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const DB_PATH = path.join(DATA_DIR, "appvenda.sqlite");
export const db = new DatabaseSync(DB_PATH);

// Helper for password hashing using PBKDF2 with salt
export function hashPassword(password: string, salt?: string): { hash: string; salt: string } {
  const generatedSalt = salt || crypto.randomBytes(16).toString("hex");
  const hash = crypto.pbkdf2Sync(password, generatedSalt, 10000, 64, "sha512").toString("hex");
  return { hash, salt: generatedSalt };
}

export function verifyPassword(password: string, hash: string, salt: string): boolean {
  const computed = crypto.pbkdf2Sync(password, salt, 10000, 64, "sha512").toString("hex");
  return crypto.timingSafeEqual(Buffer.from(computed, "hex"), Buffer.from(hash, "hex"));
}

export function generateToken(): string {
  return crypto.randomBytes(32).toString("hex");
}

// Initialize tables
export function initDatabase() {
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      nome TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      salt TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'vendedor',
      ativo INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS config (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS vendedores (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nome TEXT NOT NULL,
      comissao_percentual REAL NOT NULL DEFAULT 0,
      ativo INTEGER NOT NULL DEFAULT 1,
      user_id INTEGER,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS produtos (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nome TEXT NOT NULL,
      marca TEXT,
      categoria TEXT,
      sabor TEXT,
      peso TEXT,
      codigo_interno TEXT,
      codigo_barras TEXT,
      custo REAL NOT NULL DEFAULT 0,
      venda REAL NOT NULL DEFAULT 0,
      estoque REAL NOT NULL DEFAULT 0,
      minimo REAL NOT NULL DEFAULT 5,
      foto TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS movimentacoes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      produto_id INTEGER NOT NULL,
      tipo TEXT NOT NULL,
      qtd REAL NOT NULL,
      qtd_anterior REAL NOT NULL,
      qtd_nova REAL NOT NULL,
      custo_unit REAL,
      motivo TEXT,
      data TEXT NOT NULL,
      user_id INTEGER
    );

    CREATE TABLE IF NOT EXISTS clientes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nome TEXT NOT NULL,
      telefone TEXT,
      whatsapp TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS vendas (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      data TEXT NOT NULL,
      cliente_id INTEGER,
      vendedor_id INTEGER,
      subtotal REAL NOT NULL,
      desconto REAL NOT NULL DEFAULT 0,
      total REAL NOT NULL,
      lucro REAL NOT NULL DEFAULT 0,
      forma_pagamento TEXT NOT NULL,
      data_prevista TEXT,
      user_id INTEGER,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS itens_venda (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      venda_id INTEGER NOT NULL,
      produto_id INTEGER NOT NULL,
      nome TEXT NOT NULL,
      qtd REAL NOT NULL,
      preco_unit REAL NOT NULL,
      custo_unit REAL NOT NULL,
      subtotal REAL NOT NULL,
      FOREIGN KEY (venda_id) REFERENCES vendas(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS devedores (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nome TEXT NOT NULL,
      telefone TEXT,
      cliente_id INTEGER,
      data_prevista TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS movimentos_devedor (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      devedor_id INTEGER NOT NULL,
      tipo TEXT NOT NULL,
      valor REAL NOT NULL,
      obs TEXT,
      data TEXT NOT NULL,
      user_id INTEGER,
      FOREIGN KEY (devedor_id) REFERENCES devedores(id) ON DELETE CASCADE
    );
  `);

  // Seed default config if missing
  const setConfig = db.prepare("INSERT OR IGNORE INTO config (key, value) VALUES (?, ?)");
  setConfig.run("nomeLoja", "Loja de Suplementos & Nutrição");
  setConfig.run("logo", "");
  setConfig.run("ocultarVendasVendedor", "1"); // By default: oculta tela de venda para vendedor
  setConfig.run("versao", "2.0.0");

  // Seed default admin and vendedor users if users table is empty
  const userCountQuery = db.prepare("SELECT COUNT(*) as count FROM users");
  const result = userCountQuery.get() as { count: number };

  if (result.count === 0) {
    const now = new Date().toISOString();
    const insertUser = db.prepare(`
      INSERT INTO users (username, nome, email, password_hash, salt, role, ativo, created_at)
      VALUES (?, ?, ?, ?, ?, ?, 1, ?)
    `);

    // 1. Admin user: admin@loja.com / admin123
    const adminPass = hashPassword("admin123");
    insertUser.run("admin", "Administrador do Sistema", "admin@loja.com", adminPass.hash, adminPass.salt, "admin", now);

    // 2. Vendedor user: vendedor@loja.com / vendedor123
    const vendPass = hashPassword("vendedor123");
    insertUser.run("vendedor", "Carlos Silva (Vendedor)", "vendedor@loja.com", vendPass.hash, vendPass.salt, "vendedor", now);

    // 3. Caixa user: caixa@loja.com / caixa123
    const caixaPass = hashPassword("caixa123");
    insertUser.run("caixa", "Ana Paula (Operador de Caixa)", "caixa@loja.com", caixaPass.hash, caixaPass.salt, "caixa", now);

    // Seed default sellers
    const insertVendedor = db.prepare(`
      INSERT INTO vendedores (nome, comissao_percentual, ativo, user_id, created_at)
      VALUES (?, ?, 1, ?, ?)
    `);
    insertVendedor.run("Carlos Silva", 5.0, 2, now);
    insertVendedor.run("Mariana Santos", 6.0, null, now);
    insertVendedor.run("Lucas Lima", 4.5, null, now);

    // Seed sample products
    const insertProd = db.prepare(`
      INSERT INTO produtos (nome, marca, categoria, sabor, peso, codigo_interno, codigo_barras, custo, venda, estoque, minimo, foto, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    insertProd.run("100% Whey Protein Concentrado", "Max Titanium", "Proteínas", "Chocolate", "900g", "WHEY-MAX-01", "7891234567890", 65.00, 119.90, 18, 5, "", now, now);
    insertProd.run("Creatina Monohidratada 100% Pura", "Creapure", "Creatinas", "Neutro", "300g", "CREAT-01", "7891234567891", 45.00, 89.90, 24, 6, "", now, now);
    insertProd.run("Pré-Treino C4 Beta Pump", "New Millen", "Pré-treinos", "Frutas Vermelhas", "300g", "PRE-C4-01", "7891234567892", 52.00, 99.90, 12, 4, "", now, now);
    insertProd.run("BCAA 2400", "Growth Supplements", "Aminoácidos", "Sem sabor", "120 cáps", "BCAA-120", "7891234567893", 28.00, 54.90, 3, 5, "", now, now); // Estoque baixo
    insertProd.run("Multivitamínico Daily One", "Optimum Nutrition", "Vitaminas", "Tabletes", "90 tabs", "MULTI-01", "7891234567894", 38.00, 79.00, 15, 3, "", now, now);
    insertProd.run("Pasta de Amendoim Integral", "Dr. Peanut", "Alimentos Fit", "Avelã", "600g", "PAST-01", "7891234567895", 22.00, 44.90, 20, 5, "", now, now);
    insertProd.run("Coqueteleira Shaker Pro", "BlenderBottle", "Acessórios", "Preto Fosco", "700ml", "COQ-01", "7891234567896", 15.00, 39.90, 8, 4, "", now, now);

    // Seed sample clients
    const insertCli = db.prepare(`
      INSERT INTO clientes (nome, telefone, whatsapp, created_at)
      VALUES (?, ?, ?, ?)
    `);
    insertCli.run("Rafael Mendes", "(11) 98765-4321", "(11) 98765-4321", now);
    insertCli.run("Fernanda Souza", "(11) 97654-3210", "(11) 97654-3210", now);
    insertCli.run("Bruno Henrique", "(11) 96543-2109", "(11) 96543-2109", now);

    // Seed sample initial sales for current month and previous periods to demonstrate reports & filters
    const d1 = new Date();
    const dHoje = d1.toISOString();
    
    const dOntem = new Date(Date.now() - 86400000).toISOString();
    const d3Dias = new Date(Date.now() - 3 * 86400000).toISOString();
    const d7Dias = new Date(Date.now() - 7 * 86400000).toISOString();
    const d15Dias = new Date(Date.now() - 15 * 86400000).toISOString();
    const dPassado = new Date(Date.now() - 35 * 86400000).toISOString();

    const insertVenda = db.prepare(`
      INSERT INTO vendas (data, cliente_id, vendedor_id, subtotal, desconto, total, lucro, forma_pagamento, data_prevista, user_id, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
    `);
    const insertItem = db.prepare(`
      INSERT INTO itens_venda (venda_id, produto_id, nome, qtd, preco_unit, custo_unit, subtotal)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    // Sale 1: Hoje
    insertVenda.run(dHoje, 1, 1, 209.80, 10.00, 199.80, 89.80, "PIX", null, dHoje);
    insertItem.run(1, 1, "100% Whey Protein Concentrado", 1, 119.90, 65.00, 119.90);
    insertItem.run(1, 2, "Creatina Monohidratada 100% Pura", 1, 89.90, 45.00, 89.90);

    // Sale 2: Ontem
    insertVenda.run(dOntem, 2, 2, 99.90, 0.00, 99.90, 47.90, "Cartão", null, dOntem);
    insertItem.run(2, 3, "Pré-Treino C4 Beta Pump", 1, 99.90, 52.00, 99.90);

    // Sale 3: 3 dias atrás
    insertVenda.run(d3Dias, 3, 1, 123.90, 5.00, 118.90, 55.90, "Dinheiro", null, d3Dias);
    insertItem.run(3, 5, "Multivitamínico Daily One", 1, 79.00, 38.00, 79.00);
    insertItem.run(3, 6, "Pasta de Amendoim Integral", 1, 44.90, 22.00, 44.90);

    // Sale 4: 7 dias atrás (Fiado)
    insertVenda.run(d7Dias, 1, 2, 119.90, 0.00, 119.90, 54.90, "Fiado", new Date(Date.now() + 5*86400000).toISOString().slice(0, 10), d7Dias);
    insertItem.run(4, 1, "100% Whey Protein Concentrado", 1, 119.90, 65.00, 119.90);

    // Create debtor entry for fiado sale
    const insertDevedor = db.prepare(`
      INSERT INTO devedores (nome, telefone, cliente_id, data_prevista, created_at)
      VALUES (?, ?, ?, ?, ?)
    `);
    insertDevedor.run("Rafael Mendes", "(11) 98765-4321", 1, new Date(Date.now() + 5*86400000).toISOString().slice(0, 10), d7Dias);
    const insertMovDev = db.prepare(`
      INSERT INTO movimentos_devedor (devedor_id, tipo, valor, obs, data, user_id)
      VALUES (?, 'divida', ?, 'Venda #4 (Fiado)', ?, 1)
    `);
    insertMovDev.run(1, 119.90, d7Dias);

    // Sale 5: 15 dias atrás
    insertVenda.run(d15Dias, 2, 3, 179.80, 10.00, 169.80, 89.80, "Cartão", null, d15Dias);
    insertItem.run(5, 2, "Creatina Monohidratada 100% Pura", 2, 89.90, 45.00, 179.80);

    // Sale 6: Mês passado
    insertVenda.run(dPassado, 3, 1, 119.90, 0.00, 119.90, 54.90, "PIX", null, dPassado);
    insertItem.run(6, 1, "100% Whey Protein Concentrado", 1, 119.90, 65.00, 119.90);
  }
}
