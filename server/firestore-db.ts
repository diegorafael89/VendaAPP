import { initializeApp, getApps, cert } from "firebase-admin/app";
import { getFirestore, Firestore, FieldValue } from "firebase-admin/firestore";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

// Load firebase-applet-config.json if available
let config: any = {};
try {
  const configPath = path.join(process.cwd(), "firebase-applet-config.json");
  if (fs.existsSync(configPath)) {
    config = JSON.parse(fs.readFileSync(configPath, "utf8"));
  }
} catch (e) {
  console.warn("[Firebase] Could not read firebase-applet-config.json:", e);
}

const projectId = config.projectId || process.env.FIREBASE_PROJECT_ID || "omega-analyzer-5thv3";
const databaseId = config.firestoreDatabaseId || "(default)";

// Initialize Firebase Admin
if (getApps().length === 0) {
  initializeApp({
    projectId: projectId,
  });
}

export const firestore: Firestore = databaseId && databaseId !== "(default)"
  ? getFirestore(databaseId)
  : getFirestore();

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

// Atomic sequential ID generator per collection
export async function getNextSequence(collectionName: string): Promise<number> {
  const counterRef = firestore.collection("_counters").doc(collectionName);
  return await firestore.runTransaction(async (t) => {
    const doc = await t.get(counterRef);
    let nextId = 1;
    if (doc.exists) {
      nextId = (doc.data()?.last_id || 0) + 1;
    }
    t.set(counterRef, { last_id: nextId }, { merge: true });
    return nextId;
  });
}

// In-memory sync / Cache helper to maintain blazing fast reads and compatibility
export class CloudDatabase {
  private inited = false;

  async init() {
    if (this.inited) return;
    try {
      // Check if users exist in Firestore
      const usersSnap = await firestore.collection("users").limit(1).get();
      if (usersSnap.empty) {
        await this.seedInitialData();
      }
      this.inited = true;
      console.log("[Firebase Firestore] Banco de dados em nuvem conectado e inicializado com sucesso.");
    } catch (err: any) {
      console.error("[Firebase Firestore] Erro ao inicializar banco de dados:", err.message || err);
    }
  }

  private async seedInitialData() {
    console.log("[Firebase Firestore] Semeando dados padrão em nuvem...");
    const now = new Date().toISOString();

    // 1. Configs
    const configData: Record<string, string> = {
      nomeLoja: "Loja de Suplementos & Nutrição",
      logo: "",
      ocultarVendasVendedor: "1",
      versao: "2.0.0",
      pinAdmin: "",
    };
    for (const [key, value] of Object.entries(configData)) {
      await firestore.collection("config").doc(key).set({ key, value });
    }

    // 2. Users
    const adminPass = hashPassword("admin123");
    await firestore.collection("users").doc("1").set({
      id: 1,
      username: "admin",
      nome: "Administrador do Sistema",
      email: "admin@loja.com",
      password_hash: adminPass.hash,
      salt: adminPass.salt,
      role: "admin",
      ativo: 1,
      created_at: now,
    });

    const vendPass = hashPassword("vendedor123");
    await firestore.collection("users").doc("2").set({
      id: 2,
      username: "vendedor",
      nome: "Carlos Silva (Vendedor)",
      email: "vendedor@loja.com",
      password_hash: vendPass.hash,
      salt: vendPass.salt,
      role: "vendedor",
      ativo: 1,
      created_at: now,
    });

    const caixaPass = hashPassword("caixa123");
    await firestore.collection("users").doc("3").set({
      id: 3,
      username: "caixa",
      nome: "Ana Paula (Operador de Caixa)",
      email: "caixa@loja.com",
      password_hash: caixaPass.hash,
      salt: caixaPass.salt,
      role: "caixa",
      ativo: 1,
      created_at: now,
    });
    await firestore.collection("_counters").doc("users").set({ last_id: 3 });

    // 3. Vendedores
    const defaultVendedores = [
      { id: 1, nome: "Carlos Silva", comissao_percentual: 5.0, ativo: 1, user_id: 2, created_at: now },
      { id: 2, nome: "Mariana Santos", comissao_percentual: 6.0, ativo: 1, user_id: null, created_at: now },
      { id: 3, nome: "Lucas Lima", comissao_percentual: 4.5, ativo: 1, user_id: null, created_at: now },
    ];
    for (const v of defaultVendedores) {
      await firestore.collection("vendedores").doc(String(v.id)).set(v);
    }
    await firestore.collection("_counters").doc("vendedores").set({ last_id: 3 });

    // 4. Produtos
    const defaultProdutos = [
      { id: 1, nome: "100% Whey Protein Concentrado", marca: "Max Titanium", categoria: "Proteínas", sabor: "Chocolate", peso: "900g", codigo_interno: "WHEY-MAX-01", codigo_barras: "7891234567890", custo: 65.0, venda: 119.9, estoque: 18, minimo: 5, foto: "", created_at: now, updated_at: now },
      { id: 2, nome: "Creatina Monohidratada 100% Pura", marca: "Creapure", categoria: "Creatinas", sabor: "Neutro", peso: "300g", codigo_interno: "CREAT-01", codigo_barras: "7891234567891", custo: 45.0, venda: 89.9, estoque: 24, minimo: 6, foto: "", created_at: now, updated_at: now },
      { id: 3, nome: "Pré-Treino C4 Beta Pump", marca: "New Millen", categoria: "Pré-treinos", sabor: "Frutas Vermelhas", peso: "300g", codigo_interno: "PRE-C4-01", codigo_barras: "7891234567892", custo: 52.0, venda: 99.9, estoque: 12, minimo: 4, foto: "", created_at: now, updated_at: now },
      { id: 4, nome: "BCAA 2400", marca: "Growth Supplements", categoria: "Aminoácidos", sabor: "Sem sabor", peso: "120 cáps", codigo_interno: "BCAA-120", codigo_barras: "7891234567893", custo: 28.0, venda: 54.9, estoque: 3, minimo: 5, foto: "", created_at: now, updated_at: now },
      { id: 5, nome: "Multivitamínico Daily One", marca: "Optimum Nutrition", categoria: "Vitaminas", sabor: "Tabletes", peso: "90 tabs", codigo_interno: "MULTI-01", codigo_barras: "7891234567894", custo: 38.0, venda: 79.0, estoque: 15, minimo: 3, foto: "", created_at: now, updated_at: now },
      { id: 6, nome: "Pasta de Amendoim Integral", marca: "Dr. Peanut", categoria: "Alimentos Fit", sabor: "Avelã", peso: "600g", codigo_interno: "PAST-01", codigo_barras: "7891234567895", custo: 22.0, venda: 44.9, estoque: 20, minimo: 5, foto: "", created_at: now, updated_at: now },
      { id: 7, nome: "Coqueteleira Shaker Pro", marca: "BlenderBottle", categoria: "Acessórios", sabor: "Preto Fosco", peso: "700ml", codigo_interno: "COQ-01", codigo_barras: "7891234567896", custo: 15.0, venda: 39.9, estoque: 8, minimo: 4, foto: "", created_at: now, updated_at: now },
    ];
    for (const p of defaultProdutos) {
      await firestore.collection("produtos").doc(String(p.id)).set(p);
    }
    await firestore.collection("_counters").doc("produtos").set({ last_id: 7 });

    // 5. Clientes
    const defaultClientes = [
      { id: 1, nome: "Rafael Mendes", telefone: "(11) 98765-4321", whatsapp: "(11) 98765-4321", created_at: now },
      { id: 2, nome: "Fernanda Souza", telefone: "(11) 97654-3210", whatsapp: "(11) 97654-3210", created_at: now },
      { id: 3, nome: "Bruno Henrique", telefone: "(11) 96543-2109", whatsapp: "(11) 96543-2109", created_at: now },
    ];
    for (const c of defaultClientes) {
      await firestore.collection("clientes").doc(String(c.id)).set(c);
    }
    await firestore.collection("_counters").doc("clientes").set({ last_id: 3 });

    // 6. Vendas e Devedores iniciais
    const dHoje = new Date().toISOString();
    const dOntem = new Date(Date.now() - 86400000).toISOString();
    const d3Dias = new Date(Date.now() - 3 * 86400000).toISOString();
    const d7Dias = new Date(Date.now() - 7 * 86400000).toISOString();
    const d15Dias = new Date(Date.now() - 15 * 86400000).toISOString();

    const sampleSales = [
      { id: 1, data: dHoje, cliente_id: 1, vendedor_id: 1, subtotal: 209.8, desconto: 10.0, total: 199.8, lucro: 89.8, forma_pagamento: "PIX", data_prevista: null, user_id: 1, created_at: dHoje },
      { id: 2, data: dOntem, cliente_id: 2, vendedor_id: 2, subtotal: 99.9, desconto: 0.0, total: 99.9, lucro: 47.9, forma_pagamento: "Cartão", data_prevista: null, user_id: 1, created_at: dOntem },
      { id: 3, data: d3Dias, cliente_id: 3, vendedor_id: 1, subtotal: 123.9, desconto: 5.0, total: 118.9, lucro: 55.9, forma_pagamento: "Dinheiro", data_prevista: null, user_id: 1, created_at: d3Dias },
      { id: 4, data: d7Dias, cliente_id: 1, vendedor_id: 2, subtotal: 119.9, desconto: 0.0, total: 119.9, lucro: 54.9, forma_pagamento: "Fiado", data_prevista: new Date(Date.now() + 5*86400000).toISOString().slice(0, 10), user_id: 1, created_at: d7Dias },
      { id: 5, data: d15Dias, cliente_id: 2, vendedor_id: 3, subtotal: 179.8, desconto: 10.0, total: 169.8, lucro: 89.8, forma_pagamento: "Cartão", data_prevista: null, user_id: 1, created_at: d15Dias },
    ];
    for (const s of sampleSales) {
      await firestore.collection("vendas").doc(String(s.id)).set(s);
    }
    await firestore.collection("_counters").doc("vendas").set({ last_id: 5 });

    const sampleItems = [
      { id: 1, venda_id: 1, produto_id: 1, nome: "100% Whey Protein Concentrado", qtd: 1, preco_unit: 119.9, custo_unit: 65.0, subtotal: 119.9 },
      { id: 2, venda_id: 1, produto_id: 2, nome: "Creatina Monohidratada 100% Pura", qtd: 1, preco_unit: 89.9, custo_unit: 45.0, subtotal: 89.9 },
      { id: 3, venda_id: 2, produto_id: 3, nome: "Pré-Treino C4 Beta Pump", qtd: 1, preco_unit: 99.9, custo_unit: 52.0, subtotal: 99.9 },
      { id: 4, venda_id: 3, produto_id: 5, nome: "Multivitamínico Daily One", qtd: 1, preco_unit: 79.0, custo_unit: 38.0, subtotal: 79.0 },
      { id: 5, venda_id: 3, produto_id: 6, nome: "Pasta de Amendoim Integral", qtd: 1, preco_unit: 44.9, custo_unit: 22.0, subtotal: 44.9 },
      { id: 6, venda_id: 4, produto_id: 1, nome: "100% Whey Protein Concentrado", qtd: 1, preco_unit: 119.9, custo_unit: 65.0, subtotal: 119.9 },
      { id: 7, venda_id: 5, produto_id: 2, nome: "Creatina Monohidratada 100% Pura", qtd: 2, preco_unit: 89.9, custo_unit: 45.0, subtotal: 179.8 },
    ];
    for (const it of sampleItems) {
      await firestore.collection("itens_venda").doc(String(it.id)).set(it);
    }
    await firestore.collection("_counters").doc("itens_venda").set({ last_id: 7 });

    // Devedores
    await firestore.collection("devedores").doc("1").set({
      id: 1,
      nome: "Rafael Mendes",
      telefone: "(11) 98765-4321",
      cliente_id: 1,
      data_prevista: new Date(Date.now() + 5*86400000).toISOString().slice(0, 10),
      created_at: d7Dias,
    });
    await firestore.collection("movimentos_devedor").doc("1").set({
      id: 1,
      devedor_id: 1,
      tipo: "divida",
      valor: 119.9,
      obs: "Venda #4 (Fiado)",
      data: d7Dias,
      user_id: 1,
    });
    await firestore.collection("_counters").doc("devedores").set({ last_id: 1 });
    await firestore.collection("_counters").doc("movimentos_devedor").set({ last_id: 1 });

    console.log("[Firebase Firestore] Dados padrão inicializados.");
  }
}

export const cloudDb = new CloudDatabase();
