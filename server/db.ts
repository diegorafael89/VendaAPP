import { DatabaseSync } from "node:sqlite";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { firestore, cloudDb, getNextSequence } from "./firestore-db.ts";

// Ensure data directory exists for local cache
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

// Initialize tables in SQLite local cache
export function initDatabase() {
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY,
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
      id INTEGER PRIMARY KEY,
      nome TEXT NOT NULL,
      comissao_percentual REAL NOT NULL DEFAULT 0,
      ativo INTEGER NOT NULL DEFAULT 1,
      user_id INTEGER,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS produtos (
      id INTEGER PRIMARY KEY,
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
      id INTEGER PRIMARY KEY,
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
      id INTEGER PRIMARY KEY,
      nome TEXT NOT NULL,
      telefone TEXT,
      whatsapp TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS vendas (
      id INTEGER PRIMARY KEY,
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
      id INTEGER PRIMARY KEY,
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
      id INTEGER PRIMARY KEY,
      nome TEXT NOT NULL,
      telefone TEXT,
      cliente_id INTEGER,
      data_prevista TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS movimentos_devedor (
      id INTEGER PRIMARY KEY,
      devedor_id INTEGER NOT NULL,
      tipo TEXT NOT NULL,
      valor REAL NOT NULL,
      obs TEXT,
      data TEXT NOT NULL,
      user_id INTEGER,
      FOREIGN KEY (devedor_id) REFERENCES devedores(id) ON DELETE CASCADE
    );
  `);

  // Migrate users table with comissao_percentual if not exists
  try {
    db.exec("ALTER TABLE users ADD COLUMN comissao_percentual REAL DEFAULT 5");
  } catch (e) {
    // Column already exists
  }

  // Ensure default users exist in local cache immediately
  seedDefaultUsersIfMissing();
  syncVendedoresWithUsers();
}

export function syncVendedoresWithUsers(): void {
  try {
    const vendedoresUsers = db.prepare("SELECT * FROM users WHERE role IN ('vendedor', 'caixa')").all() as any[];
    const now = new Date().toISOString();

    for (const u of vendedoresUsers) {
      const existing = db.prepare("SELECT * FROM vendedores WHERE user_id = ? OR LOWER(nome) = LOWER(?)").get(u.id, u.nome.trim()) as any;
      const comissao = u.comissao_percentual !== undefined && u.comissao_percentual !== null ? Number(u.comissao_percentual) : (existing?.comissao_percentual ?? 5);

      if (existing) {
        db.prepare(`
          UPDATE vendedores
          SET nome = ?, comissao_percentual = ?, ativo = ?, user_id = ?
          WHERE id = ?
        `).run(u.nome.trim(), comissao, u.ativo ? 1 : 0, u.id, existing.id);

        FirestoreSyncService.saveVendedor({
          id: existing.id,
          nome: u.nome.trim(),
          comissao_percentual: comissao,
          ativo: u.ativo ? 1 : 0,
          user_id: u.id,
          created_at: existing.created_at || now,
        });
      } else {
        const maxIdRow = db.prepare("SELECT MAX(id) as maxId FROM vendedores").get() as any;
        const newId = (maxIdRow?.maxId || 0) + 1;

        db.prepare(`
          INSERT INTO vendedores (id, nome, comissao_percentual, ativo, user_id, created_at)
          VALUES (?, ?, ?, ?, ?, ?)
        `).run(newId, u.nome.trim(), comissao, u.ativo ? 1 : 0, u.id, u.created_at || now);

        FirestoreSyncService.saveVendedor({
          id: newId,
          nome: u.nome.trim(),
          comissao_percentual: comissao,
          ativo: u.ativo ? 1 : 0,
          user_id: u.id,
          created_at: u.created_at || now,
        });
      }
    }

    // Deactivate vendedores whose user is no longer a vendedor/caixa
    const nonVendUsers = db.prepare("SELECT id FROM users WHERE role NOT IN ('vendedor', 'caixa')").all() as any[];
    for (const nu of nonVendUsers) {
      db.prepare("UPDATE vendedores SET ativo = 0 WHERE user_id = ?").run(nu.id);
    }
  } catch (err: any) {
    console.error("[Sync Vendedores] Erro ao sincronizar vendedores com usuários:", err.message || err);
  }
}

export function seedDefaultUsersIfMissing(): void {
  try {
    const userCount = db.prepare("SELECT COUNT(*) as count FROM users").get() as any;
    if (!userCount || userCount.count === 0) {
      console.log("[Local DB] Semeando usuários padrão no SQLite...");
      const now = new Date().toISOString();
      const insertUser = db.prepare(`
        INSERT OR REPLACE INTO users (id, username, nome, email, password_hash, salt, role, ativo, comissao_percentual, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      const adminPass = hashPassword("admin123");
      insertUser.run(1, "admin", "Administrador do Sistema", "admin@loja.com", adminPass.hash, adminPass.salt, "admin", 1, 0, now);

      const vendPass = hashPassword("vendedor123");
      insertUser.run(2, "vendedor", "Carlos Silva (Vendedor & Caixa)", "vendedor@loja.com", vendPass.hash, vendPass.salt, "vendedor", 1, 5, now);

      const gerPass = hashPassword("gerente123");
      insertUser.run(3, "gerente", "Gerente Geral", "gerente@loja.com", gerPass.hash, gerPass.salt, "gerente", 1, 0, now);

      syncVendedoresWithUsers();
    }
  } catch (err: any) {
    console.error("[Local DB] Erro ao verificar/semear usuários padrão:", err.message || err);
  }
}

export function resetDefaultUsers(): void {
  const now = new Date().toISOString();
  const insertUser = db.prepare(`
    INSERT OR REPLACE INTO users (id, username, nome, email, password_hash, salt, role, ativo, comissao_percentual, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const adminPass = hashPassword("admin123");
  insertUser.run(1, "admin", "Administrador do Sistema", "admin@loja.com", adminPass.hash, adminPass.salt, "admin", 1, 0, now);
  FirestoreSyncService.saveUser({
    id: 1,
    username: "admin",
    nome: "Administrador do Sistema",
    email: "admin@loja.com",
    password_hash: adminPass.hash,
    salt: adminPass.salt,
    role: "admin",
    ativo: 1,
    comissao_percentual: 0,
    created_at: now,
  });

  const vendPass = hashPassword("vendedor123");
  insertUser.run(2, "vendedor", "Carlos Silva (Vendedor & Caixa)", "vendedor@loja.com", vendPass.hash, vendPass.salt, "vendedor", 1, 5, now);
  FirestoreSyncService.saveUser({
    id: 2,
    username: "vendedor",
    nome: "Carlos Silva (Vendedor & Caixa)",
    email: "vendedor@loja.com",
    password_hash: vendPass.hash,
    salt: vendPass.salt,
    role: "vendedor",
    ativo: 1,
    comissao_percentual: 5,
    created_at: now,
  });

  const gerPass = hashPassword("gerente123");
  insertUser.run(3, "gerente", "Gerente Geral", "gerente@loja.com", gerPass.hash, gerPass.salt, "gerente", 1, 0, now);
  FirestoreSyncService.saveUser({
    id: 3,
    username: "gerente",
    nome: "Gerente Geral",
    email: "gerente@loja.com",
    password_hash: gerPass.hash,
    salt: gerPass.salt,
    role: "gerente",
    ativo: 1,
    comissao_percentual: 0,
    created_at: now,
  });

  syncVendedoresWithUsers();
}

// Real-time synchronization layer with Cloud Firestore
export class FirestoreSyncService {
  private static synced = false;

  // Hydrate local cache directly from Cloud Firestore
  static async syncFromCloud(): Promise<void> {
    try {
      await cloudDb.init();

      console.log("[Firestore Sync] Sincronizando dados em nuvem para cache local...");

      // 1. Config
      const configSnap = await firestore.collection("config").get();
      const insertConfig = db.prepare("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)");
      configSnap.forEach((doc) => {
        const d = doc.data();
        insertConfig.run(d.key, String(d.value));
      });

      // 2. Users
      const usersSnap = await firestore.collection("users").get();
      const insertUser = db.prepare(`
        INSERT OR REPLACE INTO users (id, username, nome, email, password_hash, salt, role, ativo, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      usersSnap.forEach((doc) => {
        const u = doc.data();
        insertUser.run(
          Number(u.id || doc.id),
          u.username,
          u.nome,
          u.email,
          u.password_hash,
          u.salt,
          u.role || "vendedor",
          u.ativo !== undefined ? (u.ativo ? 1 : 0) : 1,
          u.created_at || new Date().toISOString()
        );
      });

      // 3. Sessions
      const sessionsSnap = await firestore.collection("sessions").get();
      const insertSession = db.prepare(`
        INSERT OR REPLACE INTO sessions (token, user_id, expires_at, created_at)
        VALUES (?, ?, ?, ?)
      `);
      sessionsSnap.forEach((doc) => {
        const s = doc.data();
        insertSession.run(s.token, Number(s.user_id), s.expires_at, s.created_at);
      });

      // 4. Vendedores
      const venSnap = await firestore.collection("vendedores").get();
      const insertVen = db.prepare(`
        INSERT OR REPLACE INTO vendedores (id, nome, comissao_percentual, ativo, user_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `);
      venSnap.forEach((doc) => {
        const v = doc.data();
        insertVen.run(
          Number(v.id || doc.id),
          v.nome,
          Number(v.comissao_percentual || 0),
          v.ativo !== undefined ? (v.ativo ? 1 : 0) : 1,
          v.user_id ? Number(v.user_id) : null,
          v.created_at || new Date().toISOString()
        );
      });

      // 5. Produtos
      const prodSnap = await firestore.collection("produtos").get();
      const insertProd = db.prepare(`
        INSERT OR REPLACE INTO produtos (id, nome, marca, categoria, sabor, peso, codigo_interno, codigo_barras, custo, venda, estoque, minimo, foto, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      prodSnap.forEach((doc) => {
        const p = doc.data();
        insertProd.run(
          Number(p.id || doc.id),
          p.nome,
          p.marca || "",
          p.categoria || "",
          p.sabor || "",
          p.peso || "",
          p.codigo_interno || "",
          p.codigo_barras || "",
          Number(p.custo || 0),
          Number(p.venda || 0),
          Number(p.estoque || 0),
          Number(p.minimo || 5),
          p.foto || "",
          p.created_at || new Date().toISOString(),
          p.updated_at || new Date().toISOString()
        );
      });

      // 6. Clientes
      const cliSnap = await firestore.collection("clientes").get();
      const insertCli = db.prepare(`
        INSERT OR REPLACE INTO clientes (id, nome, telefone, whatsapp, created_at)
        VALUES (?, ?, ?, ?, ?)
      `);
      cliSnap.forEach((doc) => {
        const c = doc.data();
        insertCli.run(
          Number(c.id || doc.id),
          c.nome,
          c.telefone || "",
          c.whatsapp || "",
          c.created_at || new Date().toISOString()
        );
      });

      // 7. Vendas
      const vendasSnap = await firestore.collection("vendas").get();
      const insertVenda = db.prepare(`
        INSERT OR REPLACE INTO vendas (id, data, cliente_id, vendedor_id, subtotal, desconto, total, lucro, forma_pagamento, data_prevista, user_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      vendasSnap.forEach((doc) => {
        const v = doc.data();
        insertVenda.run(
          Number(v.id || doc.id),
          v.data,
          v.cliente_id ? Number(v.cliente_id) : null,
          v.vendedor_id ? Number(v.vendedor_id) : null,
          Number(v.subtotal || 0),
          Number(v.desconto || 0),
          Number(v.total || 0),
          Number(v.lucro || 0),
          v.forma_pagamento || "Dinheiro",
          v.data_prevista || null,
          v.user_id ? Number(v.user_id) : null,
          v.created_at || v.data
        );
      });

      // 8. Itens Venda
      const itensSnap = await firestore.collection("itens_venda").get();
      const insertItem = db.prepare(`
        INSERT OR REPLACE INTO itens_venda (id, venda_id, produto_id, nome, qtd, preco_unit, custo_unit, subtotal)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `);
      itensSnap.forEach((doc) => {
        const it = doc.data();
        insertItem.run(
          Number(it.id || doc.id),
          Number(it.venda_id),
          Number(it.produto_id),
          it.nome,
          Number(it.qtd),
          Number(it.preco_unit),
          Number(it.custo_unit || 0),
          Number(it.subtotal || 0)
        );
      });

      // 9. Devedores
      const devSnap = await firestore.collection("devedores").get();
      const insertDev = db.prepare(`
        INSERT OR REPLACE INTO devedores (id, nome, telefone, cliente_id, data_prevista, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `);
      devSnap.forEach((doc) => {
        const d = doc.data();
        insertDev.run(
          Number(d.id || doc.id),
          d.nome,
          d.telefone || "",
          d.cliente_id ? Number(d.cliente_id) : null,
          d.data_prevista || null,
          d.created_at || new Date().toISOString()
        );
      });

      // 10. Movimentos Devedor
      const movDevSnap = await firestore.collection("movimentos_devedor").get();
      const insertMovDev = db.prepare(`
        INSERT OR REPLACE INTO movimentos_devedor (id, devedor_id, tipo, valor, obs, data, user_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `);
      movDevSnap.forEach((doc) => {
        const m = doc.data();
        insertMovDev.run(
          Number(m.id || doc.id),
          Number(m.devedor_id),
          m.tipo,
          Number(m.valor),
          m.obs || "",
          m.data,
          m.user_id ? Number(m.user_id) : null
        );
      });

      // 11. Movimentações Estoque
      const movSnap = await firestore.collection("movimentacoes").get();
      const insertMov = db.prepare(`
        INSERT OR REPLACE INTO movimentacoes (id, produto_id, tipo, qtd, qtd_anterior, qtd_nova, custo_unit, motivo, data, user_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      movSnap.forEach((doc) => {
        const m = doc.data();
        insertMov.run(
          Number(m.id || doc.id),
          Number(m.produto_id),
          m.tipo,
          Number(m.qtd),
          Number(m.qtd_anterior),
          Number(m.qtd_nova),
          Number(m.custo_unit || 0),
          m.motivo || "",
          m.data,
          m.user_id ? Number(m.user_id) : null
        );
      });

      this.synced = true;
      console.log("[Firestore Sync] Todos os dados em nuvem sincronizados com sucesso.");

      // Start continuous real-time listeners on server as well
      this.startRealtimeListeners();
    } catch (e: any) {
      console.error("[Firestore Sync] Erro na sincronização com a nuvem:", e.message || e);
    }
  }

  // Server-side continuous listeners to keep SQLite cache synchronized with cloud changes
  static startRealtimeListeners() {
    try {
      firestore.collection("produtos").onSnapshot((snapshot) => {
        const insertProd = db.prepare(`
          INSERT OR REPLACE INTO produtos (id, nome, marca, categoria, sabor, peso, codigo_interno, codigo_barras, custo, venda, estoque, minimo, foto, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);
        snapshot.docChanges().forEach((change) => {
          if (change.type === "removed") {
            const id = Number(change.doc.data().id || change.doc.id);
            db.prepare("DELETE FROM produtos WHERE id = ?").run(id);
          } else {
            const p = change.doc.data();
            insertProd.run(
              Number(p.id || change.doc.id),
              p.nome || "",
              p.marca || "",
              p.categoria || "",
              p.sabor || "",
              p.peso || "",
              p.codigo_interno || "",
              p.codigo_barras || "",
              Number(p.custo || 0),
              Number(p.venda || 0),
              Number(p.estoque || 0),
              Number(p.minimo || 5),
              p.foto || "",
              p.created_at || new Date().toISOString(),
              p.updated_at || new Date().toISOString()
            );
          }
        });
      });

      firestore.collection("movimentacoes").onSnapshot((snapshot) => {
        const insertMov = db.prepare(`
          INSERT OR REPLACE INTO movimentacoes (id, produto_id, tipo, qtd, qtd_anterior, qtd_nova, custo_unit, motivo, data, user_id)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);
        snapshot.docChanges().forEach((change) => {
          if (change.type !== "removed") {
            const m = change.doc.data();
            insertMov.run(
              Number(m.id || change.doc.id),
              Number(m.produto_id),
              m.tipo || "ajuste",
              Number(m.qtd || 0),
              Number(m.qtd_anterior || 0),
              Number(m.qtd_nova || 0),
              Number(m.custo_unit || 0),
              m.motivo || "",
              m.data || new Date().toISOString(),
              m.user_id ? Number(m.user_id) : null
            );
          }
        });
      });
    } catch (err: any) {
      console.warn("[Firestore Realtime Server] Erro ao iniciar listeners:", err.message || err);
    }
  }

  // Cloud Write-Through helpers (writes to Firestore asynchronously to ensure durability)
  static async saveConfig(key: string, value: string) {
    try {
      await firestore.collection("config").doc(key).set({ key, value });
    } catch (e) {
      console.error(`[Firestore Sync] Erro ao salvar config ${key}:`, e);
    }
  }

  static async saveUser(user: any) {
    try {
      await firestore.collection("users").doc(String(user.id)).set(user);
    } catch (e) {
      console.error(`[Firestore Sync] Erro ao salvar user ${user.id}:`, e);
    }
  }

  static async deleteUser(id: number) {
    try {
      await firestore.collection("users").doc(String(id)).delete();
    } catch (e) {
      console.error(`[Firestore Sync] Erro ao deletar user ${id}:`, e);
    }
  }

  static async saveSession(session: any) {
    try {
      await firestore.collection("sessions").doc(session.token).set(session);
    } catch (e) {
      console.error("[Firestore Sync] Erro ao salvar session:", e);
    }
  }

  static async deleteSession(token: string) {
    try {
      await firestore.collection("sessions").doc(token).delete();
    } catch (e) {
      console.error("[Firestore Sync] Erro ao deletar session:", e);
    }
  }

  static async saveProduto(produto: any) {
    try {
      await firestore.collection("produtos").doc(String(produto.id)).set(produto);
    } catch (e) {
      console.error(`[Firestore Sync] Erro ao salvar produto ${produto.id}:`, e);
    }
  }

  static async deleteProduto(id: number) {
    try {
      await firestore.collection("produtos").doc(String(id)).delete();
    } catch (e) {
      console.error(`[Firestore Sync] Erro ao deletar produto ${id}:`, e);
    }
  }

  static async saveCliente(cliente: any) {
    try {
      await firestore.collection("clientes").doc(String(cliente.id)).set(cliente);
    } catch (e) {
      console.error(`[Firestore Sync] Erro ao salvar cliente ${cliente.id}:`, e);
    }
  }

  static async deleteCliente(id: number) {
    try {
      await firestore.collection("clientes").doc(String(id)).delete();
    } catch (e) {
      console.error(`[Firestore Sync] Erro ao deletar cliente ${id}:`, e);
    }
  }

  static async saveVendedor(vendedor: any) {
    try {
      await firestore.collection("vendedores").doc(String(vendedor.id)).set(vendedor);
    } catch (e) {
      console.error(`[Firestore Sync] Erro ao salvar vendedor ${vendedor.id}:`, e);
    }
  }

  static async deleteVendedor(id: number) {
    try {
      await firestore.collection("vendedores").doc(String(id)).delete();
    } catch (e) {
      console.error(`[Firestore Sync] Erro ao deletar vendedor ${id}:`, e);
    }
  }

  static async saveVenda(venda: any, itens: any[], movimentacoes: any[], devedorData?: any) {
    try {
      const batch = firestore.batch();
      // Venda
      batch.set(firestore.collection("vendas").doc(String(venda.id)), venda);

      // Itens
      for (const item of itens) {
        batch.set(firestore.collection("itens_venda").doc(String(item.id)), item);
      }

      // Movimentações estoque & atualização estoque produtos
      for (const m of movimentacoes) {
        batch.set(firestore.collection("movimentacoes").doc(String(m.id)), m);
        batch.update(firestore.collection("produtos").doc(String(m.produto_id)), {
          estoque: m.qtd_nova,
          updated_at: m.data,
        });
      }

      // Se fiado
      if (devedorData) {
        if (devedorData.isNew) {
          batch.set(firestore.collection("devedores").doc(String(devedorData.devedor.id)), devedorData.devedor);
        } else if (devedorData.data_prevista) {
          batch.update(firestore.collection("devedores").doc(String(devedorData.devedor.id)), {
            data_prevista: devedorData.data_prevista,
          });
        }
        batch.set(firestore.collection("movimentos_devedor").doc(String(devedorData.movimento.id)), devedorData.movimento);
      }

      await batch.commit();
    } catch (e) {
      console.error(`[Firestore Sync] Erro ao salvar venda ${venda.id} em nuvem:`, e);
    }
  }

  static async cancelVenda(vendaId: number, restoredProducts: any[], restoredMovs: any[]) {
    try {
      const batch = firestore.batch();
      batch.delete(firestore.collection("vendas").doc(String(vendaId)));

      // Delete items
      const itensSnap = await firestore.collection("itens_venda").where("venda_id", "==", vendaId).get();
      itensSnap.forEach((doc) => {
        batch.delete(doc.ref);
      });

      // Restore stock
      for (const p of restoredProducts) {
        batch.update(firestore.collection("produtos").doc(String(p.id)), {
          estoque: p.novoEstoque,
          updated_at: new Date().toISOString(),
        });
      }

      for (const m of restoredMovs) {
        batch.set(firestore.collection("movimentacoes").doc(String(m.id)), m);
      }

      await batch.commit();
    } catch (e) {
      console.error(`[Firestore Sync] Erro ao cancelar venda ${vendaId} em nuvem:`, e);
    }
  }

  static async saveMovimentacaoEstoque(mov: any, produtoId: number, novoEstoque: number, novoCusto: number) {
    try {
      const batch = firestore.batch();
      batch.set(firestore.collection("movimentacoes").doc(String(mov.id)), mov);
      batch.update(firestore.collection("produtos").doc(String(produtoId)), {
        estoque: novoEstoque,
        custo: novoCusto,
        updated_at: mov.data,
      });
      await batch.commit();
    } catch (e) {
      console.error(`[Firestore Sync] Erro ao salvar movimentacao de estoque em nuvem:`, e);
    }
  }

  static async saveDevedor(devedor: any, movimentoInicial?: any) {
    try {
      const batch = firestore.batch();
      batch.set(firestore.collection("devedores").doc(String(devedor.id)), devedor);
      if (movimentoInicial) {
        batch.set(firestore.collection("movimentos_devedor").doc(String(movimentoInicial.id)), movimentoInicial);
      }
      await batch.commit();
    } catch (e) {
      console.error(`[Firestore Sync] Erro ao salvar devedor em nuvem:`, e);
    }
  }

  static async saveMovimentoDevedor(mov: any) {
    try {
      await firestore.collection("movimentos_devedor").doc(String(mov.id)).set(mov);
    } catch (e) {
      console.error(`[Firestore Sync] Erro ao salvar movimento devedor em nuvem:`, e);
    }
  }

  static async restoreFullCloudBackup(backupData: any) {
    try {
      console.log("[Firestore Sync] Restaurando backup completo em nuvem...");
      // Wipe collections
      const collections = ["produtos", "clientes", "vendedores", "vendas", "itens_venda", "devedores", "movimentos_devedor", "movimentacoes"];
      for (const col of collections) {
        const snap = await firestore.collection(col).get();
        const batch = firestore.batch();
        snap.forEach((doc) => batch.delete(doc.ref));
        await batch.commit();
      }

      // Re-populate produtos
      if (Array.isArray(backupData.produtos)) {
        for (const p of backupData.produtos) {
          await firestore.collection("produtos").doc(String(p.id)).set(p);
        }
      }
      // Re-populate clientes
      if (Array.isArray(backupData.clientes)) {
        for (const c of backupData.clientes) {
          await firestore.collection("clientes").doc(String(c.id)).set(c);
        }
      }
      // Re-populate vendedores
      if (Array.isArray(backupData.vendedores)) {
        for (const v of backupData.vendedores) {
          await firestore.collection("vendedores").doc(String(v.id)).set(v);
        }
      }
      // Re-populate vendas & itens
      if (Array.isArray(backupData.vendas)) {
        for (const v of backupData.vendas) {
          await firestore.collection("vendas").doc(String(v.id)).set(v);
        }
      }
      if (Array.isArray(backupData.itens_venda)) {
        for (const it of backupData.itens_venda) {
          await firestore.collection("itens_venda").doc(String(it.id)).set(it);
        }
      }
      // Re-populate devedores & movimentos
      if (Array.isArray(backupData.devedores)) {
        for (const d of backupData.devedores) {
          await firestore.collection("devedores").doc(String(d.id)).set(d);
        }
      }
      if (Array.isArray(backupData.movimentos_devedor)) {
        for (const m of backupData.movimentos_devedor) {
          await firestore.collection("movimentos_devedor").doc(String(m.id)).set(m);
        }
      }
      console.log("[Firestore Sync] Restauração completa do backup em nuvem finalizada.");
    } catch (e) {
      console.error("[Firestore Sync] Erro ao restaurar backup completo em nuvem:", e);
    }
  }
}
