import express, { Request, Response, NextFunction } from "express";
import path from "path";
import { createServer as createViteServer } from "vite";
import {
  db,
  initDatabase,
  hashPassword,
  verifyPassword,
  generateToken,
  FirestoreSyncService,
} from "./server/db.ts";
import { getNextSequence } from "./server/firestore-db.ts";

// Initialize tables in SQLite local cache
initDatabase();

// Hydrate from Cloud Firestore
FirestoreSyncService.syncFromCloud().catch((err) => {
  console.error("Erro ao sincronizar com Firestore:", err);
});

const app = express();
const PORT = 3000;

// Body parser
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));

// Type definition for authenticated requests
interface AuthRequest extends Request {
  user?: {
    id: number;
    username: string;
    nome: string;
    email: string;
    role: string;
    ativo: number;
  };
}

// Authentication middleware
function authMiddleware(req: AuthRequest, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.status(401).json({ error: "Não autenticado. Token não fornecido." });
    return;
  }

  const token = authHeader.substring(7);
  try {
    const sessionQuery = db.prepare(`
      SELECT s.token, s.expires_at, u.id, u.username, u.nome, u.email, u.role, u.ativo
      FROM sessions s
      JOIN users u ON s.user_id = u.id
      WHERE s.token = ?
    `);
    const session = sessionQuery.get(token) as any;

    if (!session) {
      res.status(401).json({ error: "Sessão inválida ou expirada." });
      return;
    }

    if (new Date(session.expires_at) < new Date()) {
      db.prepare("DELETE FROM sessions WHERE token = ?").run(token);
      FirestoreSyncService.deleteSession(token);
      res.status(401).json({ error: "Sessão expirada. Faça login novamente." });
      return;
    }

    if (!session.ativo) {
      res.status(403).json({ error: "Usuário desativado pelo administrador." });
      return;
    }

    req.user = {
      id: session.id,
      username: session.username,
      nome: session.nome,
      email: session.email,
      role: session.role,
      ativo: session.ativo,
    };
    next();
  } catch (err: any) {
    console.error("Erro na autenticação:", err);
    res.status(500).json({ error: "Erro interno de autenticação." });
  }
}

// Role restriction helper
function requireRole(allowedRoles: string[]) {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      res.status(401).json({ error: "Não autenticado." });
      return;
    }
    if (!allowedRoles.includes(req.user.role)) {
      res.status(403).json({ error: "Acesso negado para o seu perfil de usuário." });
      return;
    }
    next();
  };
}

// Config helper
function getConfigValue(key: string, defaultValue: string = ""): string {
  const row = db.prepare("SELECT value FROM config WHERE key = ?").get(key) as any;
  return row ? row.value : defaultValue;
}

// Health check
app.get("/api/health", (req: Request, res: Response) => {
  res.json({ status: "ok", app: "AppVenda", database: "Firebase Firestore + Cache", version: "2.0.0" });
});

/* ========================================================================== */
/*                               API: AUTH & USERS                            */
/* ========================================================================== */

// Login
app.post("/api/auth/login", (req: Request, res: Response) => {
  try {
    const { identifier, password } = req.body;
    if (!identifier || !password) {
      res.status(400).json({ error: "Usuário/email e senha são obrigatórios." });
      return;
    }

    const userQuery = db.prepare(`
      SELECT id, username, nome, email, password_hash, salt, role, ativo
      FROM users
      WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)
    `);
    const user = userQuery.get(identifier.trim(), identifier.trim()) as any;

    if (!user) {
      res.status(401).json({ error: "Credenciais inválidas." });
      return;
    }

    if (!user.ativo) {
      res.status(403).json({ error: "Este usuário está desativado. Contate o administrador." });
      return;
    }

    const valid = verifyPassword(password, user.password_hash, user.salt);
    if (!valid) {
      res.status(401).json({ error: "Credenciais inválidas." });
      return;
    }

    const token = generateToken();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(); // 7 days
    const now = new Date().toISOString();

    db.prepare(`
      INSERT INTO sessions (token, user_id, expires_at, created_at)
      VALUES (?, ?, ?, ?)
    `).run(token, user.id, expiresAt, now);

    FirestoreSyncService.saveSession({
      token,
      user_id: user.id,
      expires_at: expiresAt,
      created_at: now,
    });

    const ocultarVendasVendedor = getConfigValue("ocultarVendasVendedor", "1") === "1";

    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        nome: user.nome,
        email: user.email,
        role: user.role,
      },
      policies: {
        ocultarVendasVendedor,
      },
    });
  } catch (err: any) {
    console.error("Erro no login:", err);
    res.status(500).json({ error: "Erro interno no servidor ao realizar login." });
  }
});

// Current User Info
app.get("/api/auth/me", authMiddleware, (req: AuthRequest, res: Response) => {
  const ocultarVendasVendedor = getConfigValue("ocultarVendasVendedor", "1") === "1";
  res.json({
    user: req.user,
    policies: {
      ocultarVendasVendedor,
    },
  });
});

// Logout
app.post("/api/auth/logout", authMiddleware, (req: AuthRequest, res: Response) => {
  const token = req.headers.authorization?.substring(7);
  if (token) {
    db.prepare("DELETE FROM sessions WHERE token = ?").run(token);
    FirestoreSyncService.deleteSession(token);
  }
  res.json({ success: true, message: "Sessão encerrada com sucesso." });
});

// List Users (Admin only)
app.get("/api/auth/users", authMiddleware, requireRole(["admin"]), (req: AuthRequest, res: Response) => {
  try {
    const users = db.prepare(`
      SELECT id, username, nome, email, role, ativo, created_at
      FROM users
      ORDER BY id ASC
    `).all();
    res.json(users);
  } catch (err: any) {
    res.status(500).json({ error: "Erro ao listar usuários." });
  }
});

// Create User (Admin only)
app.post("/api/auth/users", authMiddleware, requireRole(["admin"]), async (req: AuthRequest, res: Response) => {
  try {
    const { username, nome, email, password, role } = req.body;
    if (!username || !nome || !email || !password || !role) {
      res.status(400).json({ error: "Todos os campos são obrigatórios." });
      return;
    }

    const existing = db.prepare(`
      SELECT id FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)
    `).get(username.trim(), email.trim());

    if (existing) {
      res.status(400).json({ error: "Já existe um usuário com este login ou e-mail." });
      return;
    }

    const { hash, salt } = hashPassword(password);
    const now = new Date().toISOString();
    const newId = await getNextSequence("users");

    db.prepare(`
      INSERT INTO users (id, username, nome, email, password_hash, salt, role, ativo, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
    `).run(newId, username.trim(), nome.trim(), email.trim(), hash, salt, role, now);

    FirestoreSyncService.saveUser({
      id: newId,
      username: username.trim(),
      nome: nome.trim(),
      email: email.trim(),
      password_hash: hash,
      salt: salt,
      role: role,
      ativo: 1,
      created_at: now,
    });

    res.json({ success: true, id: newId });
  } catch (err: any) {
    res.status(500).json({ error: "Erro ao criar usuário: " + err.message });
  }
});

// Update User (Admin only)
app.put("/api/auth/users/:id", authMiddleware, requireRole(["admin"]), (req: AuthRequest, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const { nome, email, role, ativo, password } = req.body;

    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(id) as any;
    if (!user) {
      res.status(404).json({ error: "Usuário não encontrado." });
      return;
    }

    let passwordHash = user.password_hash;
    let userSalt = user.salt;

    if (password && password.trim().length >= 4) {
      const generated = hashPassword(password.trim());
      passwordHash = generated.hash;
      userSalt = generated.salt;
    }

    db.prepare(`
      UPDATE users
      SET nome = ?, email = ?, role = ?, ativo = ?, password_hash = ?, salt = ?
      WHERE id = ?
    `).run(nome, email, role, ativo ? 1 : 0, passwordHash, userSalt, id);

    FirestoreSyncService.saveUser({
      id,
      username: user.username,
      nome: nome.trim(),
      email: email.trim(),
      role,
      ativo: ativo ? 1 : 0,
      password_hash: passwordHash,
      salt: userSalt,
      created_at: user.created_at || new Date().toISOString(),
    });

    res.json({ success: true, message: "Usuário atualizado com sucesso." });
  } catch (err: any) {
    res.status(500).json({ error: "Erro ao atualizar usuário: " + err.message });
  }
});

// Delete User (Admin only)
app.delete("/api/auth/users/:id", authMiddleware, requireRole(["admin"]), (req: AuthRequest, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    if (id === req.user?.id) {
      res.status(400).json({ error: "Você não pode excluir a sua própria conta." });
      return;
    }
    db.prepare("DELETE FROM users WHERE id = ?").run(id);
    FirestoreSyncService.deleteUser(id);
    res.json({ success: true, message: "Usuário excluído." });
  } catch (err: any) {
    res.status(500).json({ error: "Erro ao excluir usuário." });
  }
});

/* ========================================================================== */
/*                               API: CONFIGURAÇÕES                           */
/* ========================================================================== */

app.get("/api/config", (req: Request, res: Response) => {
  try {
    const rows = db.prepare("SELECT key, value FROM config").all() as any[];
    const configObj: Record<string, string> = {};
    rows.forEach((r) => {
      configObj[r.key] = r.value;
    });
    res.json(configObj);
  } catch (err: any) {
    res.status(500).json({ error: "Erro ao buscar configurações." });
  }
});

app.post("/api/config", authMiddleware, requireRole(["admin"]), (req: AuthRequest, res: Response) => {
  try {
    const { nomeLoja, logo, ocultarVendasVendedor, pinAdmin } = req.body;
    const upsert = db.prepare("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)");

    if (nomeLoja !== undefined) {
      upsert.run("nomeLoja", String(nomeLoja));
      FirestoreSyncService.saveConfig("nomeLoja", String(nomeLoja));
    }
    if (logo !== undefined) {
      upsert.run("logo", String(logo));
      FirestoreSyncService.saveConfig("logo", String(logo));
    }
    if (ocultarVendasVendedor !== undefined) {
      const val = ocultarVendasVendedor ? "1" : "0";
      upsert.run("ocultarVendasVendedor", val);
      FirestoreSyncService.saveConfig("ocultarVendasVendedor", val);
    }
    if (pinAdmin !== undefined) {
      upsert.run("pinAdmin", String(pinAdmin));
      FirestoreSyncService.saveConfig("pinAdmin", String(pinAdmin));
    }

    res.json({ success: true, message: "Configurações salvas permanentemente na nuvem." });
  } catch (err: any) {
    res.status(500).json({ error: "Erro ao salvar configurações." });
  }
});

/* ========================================================================== */
/*                               API: PRODUTOS                                */
/* ========================================================================== */

app.get("/api/produtos", authMiddleware, (req: AuthRequest, res: Response) => {
  try {
    const produtos = db.prepare("SELECT * FROM produtos ORDER BY nome ASC").all();
    res.json(produtos);
  } catch (err: any) {
    res.status(500).json({ error: "Erro ao carregar produtos." });
  }
});

app.post("/api/produtos", authMiddleware, requireRole(["admin", "gerente"]), async (req: AuthRequest, res: Response) => {
  try {
    const { nome, marca, categoria, sabor, peso, codigo_interno, codigo_barras, custo, venda, estoque, minimo, foto } = req.body;
    if (!nome || custo === undefined || venda === undefined) {
      res.status(400).json({ error: "Nome, custo e valor de venda são obrigatórios." });
      return;
    }

    const now = new Date().toISOString();
    const newId = await getNextSequence("produtos");

    const produtoData = {
      id: newId,
      nome: nome.trim(),
      marca: marca || "",
      categoria: categoria || "",
      sabor: sabor || "",
      peso: peso || "",
      codigo_interno: codigo_interno || "",
      codigo_barras: codigo_barras || "",
      custo: parseFloat(custo) || 0,
      venda: parseFloat(venda) || 0,
      estoque: parseFloat(estoque) || 0,
      minimo: parseFloat(minimo) || 5,
      foto: foto || "",
      created_at: now,
      updated_at: now,
    };

    db.prepare(`
      INSERT INTO produtos (id, nome, marca, categoria, sabor, peso, codigo_interno, codigo_barras, custo, venda, estoque, minimo, foto, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      newId,
      produtoData.nome,
      produtoData.marca,
      produtoData.categoria,
      produtoData.sabor,
      produtoData.peso,
      produtoData.codigo_interno,
      produtoData.codigo_barras,
      produtoData.custo,
      produtoData.venda,
      produtoData.estoque,
      produtoData.minimo,
      produtoData.foto,
      now,
      now
    );

    FirestoreSyncService.saveProduto(produtoData);

    res.json({ success: true, id: newId });
  } catch (err: any) {
    res.status(500).json({ error: "Erro ao salvar produto: " + err.message });
  }
});

app.put("/api/produtos/:id", authMiddleware, requireRole(["admin", "gerente"]), (req: AuthRequest, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const { nome, marca, categoria, sabor, peso, codigo_interno, codigo_barras, custo, venda, minimo, foto } = req.body;

    const existing = db.prepare("SELECT * FROM produtos WHERE id = ?").get(id) as any;
    if (!existing) {
      res.status(404).json({ error: "Produto não encontrado." });
      return;
    }

    const now = new Date().toISOString();
    const updated = {
      ...existing,
      nome: nome.trim(),
      marca: marca || "",
      categoria: categoria || "",
      sabor: sabor || "",
      peso: peso || "",
      codigo_interno: codigo_interno || "",
      codigo_barras: codigo_barras || "",
      custo: parseFloat(custo) || 0,
      venda: parseFloat(venda) || 0,
      minimo: parseFloat(minimo) || 5,
      foto: foto || "",
      updated_at: now,
    };

    db.prepare(`
      UPDATE produtos
      SET nome = ?, marca = ?, categoria = ?, sabor = ?, peso = ?, codigo_interno = ?, codigo_barras = ?, custo = ?, venda = ?, minimo = ?, foto = ?, updated_at = ?
      WHERE id = ?
    `).run(
      updated.nome,
      updated.marca,
      updated.categoria,
      updated.sabor,
      updated.peso,
      updated.codigo_interno,
      updated.codigo_barras,
      updated.custo,
      updated.venda,
      updated.minimo,
      updated.foto,
      now,
      id
    );

    FirestoreSyncService.saveProduto(updated);

    res.json({ success: true, message: "Produto atualizado na nuvem." });
  } catch (err: any) {
    res.status(500).json({ error: "Erro ao atualizar produto." });
  }
});

app.delete("/api/produtos/:id", authMiddleware, requireRole(["admin", "gerente"]), (req: AuthRequest, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    db.prepare("DELETE FROM produtos WHERE id = ?").run(id);
    FirestoreSyncService.deleteProduto(id);
    res.json({ success: true, message: "Produto excluído com sucesso." });
  } catch (err: any) {
    res.status(500).json({ error: "Erro ao excluir produto." });
  }
});

/* ========================================================================== */
/*                               API: ESTOQUE                                 */
/* ========================================================================== */

app.get("/api/estoque/movimentacoes", authMiddleware, (req: AuthRequest, res: Response) => {
  try {
    const rows = db.prepare(`
      SELECT m.*, p.nome as produto_nome, p.marca as produto_marca
      FROM movimentacoes m
      LEFT JOIN produtos p ON m.produto_id = p.id
      ORDER BY m.data DESC
      LIMIT 200
    `).all();
    res.json(rows);
  } catch (err: any) {
    res.status(500).json({ error: "Erro ao listar movimentações de estoque." });
  }
});

app.post("/api/estoque/movimentar", authMiddleware, requireRole(["admin", "gerente"]), async (req: AuthRequest, res: Response) => {
  try {
    const { produto_id, tipo, qtd, custo_unit, motivo } = req.body;
    const pId = parseInt(produto_id);
    const quantidade = parseFloat(qtd);

    if (!pId || isNaN(quantidade) || quantidade <= 0) {
      res.status(400).json({ error: "Produto e quantidade válida são obrigatórios." });
      return;
    }

    const prod = db.prepare("SELECT * FROM produtos WHERE id = ?").get(pId) as any;
    if (!prod) {
      res.status(404).json({ error: "Produto não encontrado." });
      return;
    }

    const qtdAnterior = prod.estoque;
    let novaQtd = qtdAnterior;
    let novoCusto = prod.custo;

    if (tipo === "entrada") {
      const custoUnitario = parseFloat(custo_unit) || prod.custo;
      const valorAtual = prod.estoque * prod.custo;
      const valorEntrada = quantidade * custoUnitario;
      novaQtd = prod.estoque + quantidade;
      novoCusto = novaQtd > 0 ? (valorAtual + valorEntrada) / novaQtd : custoUnitario;
    } else if (tipo === "saida") {
      if (quantidade > prod.estoque) {
        res.status(400).json({ error: `Estoque insuficiente. Disponível: ${prod.estoque}` });
        return;
      }
      novaQtd = prod.estoque - quantidade;
    } else if (tipo === "ajuste") {
      novaQtd = quantidade;
    } else {
      res.status(400).json({ error: "Tipo de movimentação inválido." });
      return;
    }

    const now = new Date().toISOString();
    const movId = await getNextSequence("movimentacoes");

    db.prepare(`
      UPDATE produtos SET estoque = ?, custo = ?, updated_at = ? WHERE id = ?
    `).run(novaQtd, novoCusto, now, pId);

    const movData = {
      id: movId,
      produto_id: pId,
      tipo,
      qtd: tipo === "ajuste" ? novaQtd - qtdAnterior : quantidade,
      qtd_anterior: qtdAnterior,
      qtd_nova: novaQtd,
      custo_unit: parseFloat(custo_unit) || prod.custo,
      motivo: motivo || "",
      data: now,
      user_id: req.user?.id || null,
    };

    db.prepare(`
      INSERT INTO movimentacoes (id, produto_id, tipo, qtd, qtd_anterior, qtd_nova, custo_unit, motivo, data, user_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      movId,
      movData.produto_id,
      movData.tipo,
      movData.qtd,
      movData.qtd_anterior,
      movData.qtd_nova,
      movData.custo_unit,
      movData.motivo,
      now,
      movData.user_id
    );

    FirestoreSyncService.saveMovimentacaoEstoque(movData, pId, novaQtd, novoCusto);

    res.json({ success: true, novoEstoque: novaQtd, novoCusto });
  } catch (err: any) {
    res.status(500).json({ error: "Erro ao processar movimentação: " + err.message });
  }
});

/* ========================================================================== */
/*                               API: VENDAS                                  */
/* ========================================================================== */

function canAccessSales(req: AuthRequest): boolean {
  if (!req.user) return false;
  const ocultar = getConfigValue("ocultarVendasVendedor", "1") === "1";
  if (req.user.role === "vendedor" && ocultar) {
    return false;
  }
  return true;
}

// List Sales with Advanced Filters
app.get("/api/vendas", authMiddleware, (req: AuthRequest, res: Response) => {
  try {
    if (!canAccessSales(req)) {
      res.status(403).json({ error: "Acesso restrito: A tela e histórico de vendas estão ocultos para perfil vendedor." });
      return;
    }

    const { de, ate, formaPagamento, vendedorId, clienteId, limite } = req.query;

    let query = `
      SELECT v.*, c.nome as cliente_nome, ven.nome as vendedor_nome, u.nome as operador_nome
      FROM vendas v
      LEFT JOIN clientes c ON v.cliente_id = c.id
      LEFT JOIN vendedores ven ON v.vendedor_id = ven.id
      LEFT JOIN users u ON v.user_id = u.id
      WHERE 1=1
    `;
    const params: any[] = [];

    if (de) {
      query += " AND DATE(v.data) >= DATE(?)";
      params.push(de);
    }
    if (ate) {
      query += " AND DATE(v.data) <= DATE(?)";
      params.push(ate);
    }
    if (formaPagamento && formaPagamento !== "todas") {
      query += " AND v.forma_pagamento = ?";
      params.push(formaPagamento);
    }
    if (vendedorId && vendedorId !== "todos") {
      query += " AND v.vendedor_id = ?";
      params.push(parseInt(vendedorId as string));
    }
    if (clienteId && clienteId !== "todos") {
      query += " AND v.cliente_id = ?";
      params.push(parseInt(clienteId as string));
    }

    query += " ORDER BY v.data DESC";

    if (limite) {
      query += ` LIMIT ${parseInt(limite as string)}`;
    } else {
      query += " LIMIT 300";
    }

    const vendas = db.prepare(query).all(...params) as any[];

    // Fetch items for each sale
    const getItens = db.prepare("SELECT * FROM itens_venda WHERE venda_id = ?");
    vendas.forEach((v) => {
      v.itens = getItens.all(v.id);
    });

    const totalFaturamento = vendas.reduce((sum, v) => sum + (v.total || 0), 0);
    const totalLucro = vendas.reduce((sum, v) => sum + (v.lucro || 0), 0);
    const totalDesconto = vendas.reduce((sum, v) => sum + (v.desconto || 0), 0);
    const qtdVendas = vendas.length;
    const ticketMedio = qtdVendas > 0 ? totalFaturamento / qtdVendas : 0;

    res.json({
      vendas,
      metricas: {
        totalFaturamento,
        totalLucro,
        totalDesconto,
        qtdVendas,
        ticketMedio,
      },
    });
  } catch (err: any) {
    res.status(500).json({ error: "Erro ao buscar vendas: " + err.message });
  }
});

// Finalize Sale
app.post("/api/vendas", authMiddleware, async (req: AuthRequest, res: Response) => {
  try {
    if (!canAccessSales(req)) {
      res.status(403).json({ error: "Operação não autorizada: Vendedores não têm acesso para registrar vendas diretamente." });
      return;
    }

    const { itens, clienteId, vendedorId, desconto, formaPagamento, dataPrevista } = req.body;

    if (!itens || !Array.isArray(itens) || itens.length === 0) {
      res.status(400).json({ error: "O carrinho de vendas não pode estar vazio." });
      return;
    }

    if (formaPagamento === "Fiado" && !clienteId) {
      res.status(400).json({ error: "Para vendas fiado, é obrigatório selecionar um cliente cadastrado." });
      return;
    }

    // Verify stock availability
    for (const item of itens) {
      const p = db.prepare("SELECT * FROM produtos WHERE id = ?").get(item.produtoId) as any;
      if (!p) {
        res.status(400).json({ error: `Produto ID ${item.produtoId} não encontrado.` });
        return;
      }
      if (p.estoque < item.qtd) {
        res.status(400).json({ error: `Estoque insuficiente para "${p.nome}". Disponível: ${p.estoque}` });
        return;
      }
    }

    const subtotal = itens.reduce((sum: number, i: any) => sum + (i.qtd * i.precoUnit), 0);
    const valDesconto = parseFloat(desconto) || 0;
    const total = Math.max(0, subtotal - valDesconto);
    const custoTotal = itens.reduce((sum: number, i: any) => sum + (i.qtd * (i.custoUnit || 0)), 0);
    const lucro = total - custoTotal;
    const now = new Date().toISOString();

    const vendaId = await getNextSequence("vendas");

    // 1. Create sale record
    const vendaData = {
      id: vendaId,
      data: now,
      cliente_id: clienteId ? parseInt(clienteId) : null,
      vendedor_id: vendedorId ? parseInt(vendedorId) : null,
      subtotal,
      desconto: valDesconto,
      total,
      lucro,
      forma_pagamento: formaPagamento || "Dinheiro",
      data_prevista: dataPrevista || null,
      user_id: req.user?.id || null,
      created_at: now,
    };

    db.prepare(`
      INSERT INTO vendas (id, data, cliente_id, vendedor_id, subtotal, desconto, total, lucro, forma_pagamento, data_prevista, user_id, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      vendaId,
      vendaData.data,
      vendaData.cliente_id,
      vendaData.vendedor_id,
      vendaData.subtotal,
      vendaData.desconto,
      vendaData.total,
      vendaData.lucro,
      vendaData.forma_pagamento,
      vendaData.data_prevista,
      vendaData.user_id,
      vendaData.created_at
    );

    // 2. Insert items and decrement stock
    const itensToSync: any[] = [];
    const movsToSync: any[] = [];

    const insertItem = db.prepare(`
      INSERT INTO itens_venda (id, venda_id, produto_id, nome, qtd, preco_unit, custo_unit, subtotal)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const updateStock = db.prepare(`
      UPDATE produtos SET estoque = estoque - ?, updated_at = ? WHERE id = ?
    `);
    const insertMov = db.prepare(`
      INSERT INTO movimentacoes (id, produto_id, tipo, qtd, qtd_anterior, qtd_nova, custo_unit, motivo, data, user_id)
      VALUES (?, ?, 'saida', ?, ?, ?, ?, ?, ?, ?)
    `);

    for (const item of itens) {
      const itemId = await getNextSequence("itens_venda");
      const movId = await getNextSequence("movimentacoes");

      const itemRecord = {
        id: itemId,
        venda_id: vendaId,
        produto_id: item.produtoId,
        nome: item.nome,
        qtd: item.qtd,
        preco_unit: item.precoUnit,
        custo_unit: item.custoUnit || 0,
        subtotal: item.qtd * item.precoUnit,
      };

      insertItem.run(
        itemRecord.id,
        itemRecord.venda_id,
        itemRecord.produto_id,
        itemRecord.nome,
        itemRecord.qtd,
        itemRecord.preco_unit,
        itemRecord.custo_unit,
        itemRecord.subtotal
      );
      itensToSync.push(itemRecord);

      const currentProd = db.prepare("SELECT estoque, custo FROM produtos WHERE id = ?").get(item.produtoId) as any;
      const novoEstoque = currentProd.estoque - item.qtd;

      updateStock.run(item.qtd, now, item.produtoId);

      const movRecord = {
        id: movId,
        produto_id: item.produtoId,
        tipo: "saida",
        qtd: item.qtd,
        qtd_anterior: currentProd.estoque,
        qtd_nova: novoEstoque,
        custo_unit: currentProd.custo,
        motivo: `Venda #${vendaId}`,
        data: now,
        user_id: req.user?.id || null,
      };

      insertMov.run(
        movRecord.id,
        movRecord.produto_id,
        movRecord.qtd,
        movRecord.qtd_anterior,
        movRecord.qtd_nova,
        movRecord.custo_unit,
        movRecord.motivo,
        movRecord.data,
        movRecord.user_id
      );
      movsToSync.push(movRecord);
    }

    // 3. If Fiado, register debt in devedores table
    let devedorDataSync: any = null;
    if (formaPagamento === "Fiado" && clienteId) {
      const cli = db.prepare("SELECT * FROM clientes WHERE id = ?").get(clienteId) as any;
      let devedor = db.prepare("SELECT id FROM devedores WHERE cliente_id = ?").get(clienteId) as any;

      let devedorId: number;
      let isNew = false;
      let devedorRecord: any = null;

      if (!devedor) {
        isNew = true;
        devedorId = await getNextSequence("devedores");
        devedorRecord = {
          id: devedorId,
          nome: cli.nome,
          telefone: cli.telefone,
          cliente_id: cli.id,
          data_prevista: dataPrevista || null,
          created_at: now,
        };
        db.prepare(`
          INSERT INTO devedores (id, nome, telefone, cliente_id, data_prevista, created_at)
          VALUES (?, ?, ?, ?, ?, ?)
        `).run(devedorId, devedorRecord.nome, devedorRecord.telefone, devedorRecord.cliente_id, devedorRecord.data_prevista, now);
      } else {
        devedorId = devedor.id;
        devedorRecord = { id: devedorId };
        if (dataPrevista) {
          db.prepare("UPDATE devedores SET data_prevista = ? WHERE id = ?").run(dataPrevista, devedorId);
        }
      }

      const movDevId = await getNextSequence("movimentos_devedor");
      const movDevRecord = {
        id: movDevId,
        devedor_id: devedorId,
        tipo: "divida",
        valor: total,
        obs: `Venda #${vendaId} (Fiado)`,
        data: now,
        user_id: req.user?.id || null,
      };

      db.prepare(`
        INSERT INTO movimentos_devedor (id, devedor_id, tipo, valor, obs, data, user_id)
        VALUES (?, ?, 'divida', ?, ?, ?, ?)
      `).run(movDevId, devedorId, movDevRecord.valor, movDevRecord.obs, now, movDevRecord.user_id);

      devedorDataSync = {
        isNew,
        devedor: devedorRecord,
        data_prevista: dataPrevista,
        movimento: movDevRecord,
      };
    }

    // Persist completely to Cloud Firestore
    FirestoreSyncService.saveVenda(vendaData, itensToSync, movsToSync, devedorDataSync);

    res.json({ success: true, vendaId, total, lucro });
  } catch (err: any) {
    res.status(500).json({ error: "Erro ao registrar venda: " + err.message });
  }
});

// Cancel Sale (Admin only)
app.delete("/api/vendas/:id", authMiddleware, requireRole(["admin"]), async (req: AuthRequest, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const venda = db.prepare("SELECT * FROM vendas WHERE id = ?").get(id) as any;
    if (!venda) {
      res.status(404).json({ error: "Venda não encontrada." });
      return;
    }

    const itens = db.prepare("SELECT * FROM itens_venda WHERE venda_id = ?").all(id) as any[];
    const updateStock = db.prepare("UPDATE produtos SET estoque = estoque + ? WHERE id = ?");
    const insertMov = db.prepare(`
      INSERT INTO movimentacoes (id, produto_id, tipo, qtd, qtd_anterior, qtd_nova, custo_unit, motivo, data, user_id)
      VALUES (?, ?, 'entrada', ?, ?, ?, ?, ?, ?, ?)
    `);
    const now = new Date().toISOString();

    const restoredProducts: any[] = [];
    const restoredMovs: any[] = [];

    for (const item of itens) {
      const prod = db.prepare("SELECT estoque, custo FROM produtos WHERE id = ?").get(item.produto_id) as any;
      if (prod) {
        const movId = await getNextSequence("movimentacoes");
        const novoEstoque = prod.estoque + item.qtd;
        updateStock.run(item.qtd, item.produto_id);

        const movData = {
          id: movId,
          produto_id: item.produto_id,
          tipo: "entrada",
          qtd: item.qtd,
          qtd_anterior: prod.estoque,
          qtd_nova: novoEstoque,
          custo_unit: prod.custo,
          motivo: `Cancelamento da venda #${id}`,
          data: now,
          user_id: req.user?.id || null,
        };

        insertMov.run(
          movData.id,
          movData.produto_id,
          movData.qtd,
          movData.qtd_anterior,
          movData.qtd_nova,
          movData.custo_unit,
          movData.motivo,
          now,
          movData.user_id
        );

        restoredProducts.push({ id: item.produto_id, novoEstoque });
        restoredMovs.push(movData);
      }
    }

    db.prepare("DELETE FROM vendas WHERE id = ?").run(id);
    db.prepare("DELETE FROM itens_venda WHERE venda_id = ?").run(id);

    FirestoreSyncService.cancelVenda(id, restoredProducts, restoredMovs);

    res.json({ success: true, message: "Venda cancelada e estoque restaurado na nuvem com sucesso." });
  } catch (err: any) {
    res.status(500).json({ error: "Erro ao cancelar venda." });
  }
});

/* ========================================================================== */
/*                               API: CLIENTES                                */
/* ========================================================================== */

app.get("/api/clientes", authMiddleware, (req: AuthRequest, res: Response) => {
  try {
    const clientes = db.prepare(`
      SELECT c.*, COUNT(v.id) as total_compras, COALESCE(SUM(v.total), 0) as total_gasto
      FROM clientes c
      LEFT JOIN vendas v ON c.id = v.cliente_id
      GROUP BY c.id
      ORDER BY c.nome ASC
    `).all();
    res.json(clientes);
  } catch (err: any) {
    res.status(500).json({ error: "Erro ao listar clientes." });
  }
});

app.post("/api/clientes", authMiddleware, async (req: AuthRequest, res: Response) => {
  try {
    const { nome, telefone, whatsapp } = req.body;
    if (!nome) {
      res.status(400).json({ error: "Nome do cliente é obrigatório." });
      return;
    }
    const newId = await getNextSequence("clientes");
    const now = new Date().toISOString();

    const cliData = {
      id: newId,
      nome: nome.trim(),
      telefone: telefone || "",
      whatsapp: whatsapp || "",
      created_at: now,
    };

    db.prepare(`
      INSERT INTO clientes (id, nome, telefone, whatsapp, created_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(newId, cliData.nome, cliData.telefone, cliData.whatsapp, now);

    FirestoreSyncService.saveCliente(cliData);

    res.json({ success: true, id: newId });
  } catch (err: any) {
    res.status(500).json({ error: "Erro ao salvar cliente." });
  }
});

app.put("/api/clientes/:id", authMiddleware, (req: AuthRequest, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const { nome, telefone, whatsapp } = req.body;

    const existing = db.prepare("SELECT * FROM clientes WHERE id = ?").get(id) as any;
    if (!existing) {
      res.status(404).json({ error: "Cliente não encontrado." });
      return;
    }

    const updated = {
      ...existing,
      nome: nome.trim(),
      telefone: telefone || "",
      whatsapp: whatsapp || "",
    };

    db.prepare(`
      UPDATE clientes SET nome = ?, telefone = ?, whatsapp = ? WHERE id = ?
    `).run(updated.nome, updated.telefone, updated.whatsapp, id);

    FirestoreSyncService.saveCliente(updated);

    res.json({ success: true, message: "Cliente atualizado na nuvem." });
  } catch (err: any) {
    res.status(500).json({ error: "Erro ao atualizar cliente." });
  }
});

app.delete("/api/clientes/:id", authMiddleware, requireRole(["admin", "gerente"]), (req: AuthRequest, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    db.prepare("DELETE FROM clientes WHERE id = ?").run(id);
    FirestoreSyncService.deleteCliente(id);
    res.json({ success: true, message: "Cliente removido." });
  } catch (err: any) {
    res.status(500).json({ error: "Erro ao excluir cliente." });
  }
});

app.get("/api/clientes/:id/historico", authMiddleware, (req: AuthRequest, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const vendas = db.prepare(`
      SELECT * FROM vendas WHERE cliente_id = ? ORDER BY data DESC
    `).all(id) as any[];

    const getItens = db.prepare("SELECT * FROM itens_venda WHERE venda_id = ?");
    vendas.forEach((v) => {
      v.itens = getItens.all(v.id);
    });

    res.json(vendas);
  } catch (err: any) {
    res.status(500).json({ error: "Erro ao buscar histórico do cliente." });
  }
});

/* ========================================================================== */
/*                               API: DEVEDORES                               */
/* ========================================================================== */

app.get("/api/devedores", authMiddleware, requireRole(["admin", "gerente", "caixa", "vendedor"]), (req: AuthRequest, res: Response) => {
  try {
    const devedores = db.prepare(`
      SELECT d.*,
        COALESCE((SELECT SUM(valor) FROM movimentos_devedor WHERE devedor_id = d.id AND tipo = 'divida'), 0) -
        COALESCE((SELECT SUM(valor) FROM movimentos_devedor WHERE devedor_id = d.id AND tipo = 'pagamento'), 0) as saldo_devedor
      FROM devedores d
      ORDER BY saldo_devedor DESC, d.nome ASC
    `).all() as any[];

    const totalReceber = devedores.reduce((sum, d) => sum + Math.max(0, d.saldo_devedor), 0);

    res.json({ devedores, totalReceber });
  } catch (err: any) {
    res.status(500).json({ error: "Erro ao listar devedores." });
  }
});

app.get("/api/devedores/:id", authMiddleware, requireRole(["admin", "gerente", "caixa", "vendedor"]), (req: AuthRequest, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const devedor = db.prepare("SELECT * FROM devedores WHERE id = ?").get(id) as any;
    if (!devedor) {
      res.status(404).json({ error: "Devedor não encontrado." });
      return;
    }

    const movimentos = db.prepare(`
      SELECT * FROM movimentos_devedor WHERE devedor_id = ? ORDER BY data DESC
    `).all(id) as any[];

    const totalDivida = movimentos.filter((m) => m.tipo === "divida").reduce((s, m) => s + m.valor, 0);
    const totalPago = movimentos.filter((m) => m.tipo === "pagamento").reduce((s, m) => s + m.valor, 0);
    const saldo = totalDivida - totalPago;

    res.json({ devedor, saldo, movimentos });
  } catch (err: any) {
    res.status(500).json({ error: "Erro ao buscar detalhes do devedor." });
  }
});

app.post("/api/devedores", authMiddleware, requireRole(["admin", "gerente", "caixa"]), async (req: AuthRequest, res: Response) => {
  try {
    const { nome, telefone, valor, dataVenda, dataPrevista } = req.body;
    if (!nome || !valor || parseFloat(valor) <= 0) {
      res.status(400).json({ error: "Nome e valor da dívida são obrigatórios." });
      return;
    }

    const now = new Date().toISOString();
    const dataOperacao = dataVenda ? new Date(dataVenda).toISOString() : now;
    const devId = await getNextSequence("devedores");
    const movId = await getNextSequence("movimentos_devedor");

    const devedorData = {
      id: devId,
      nome: nome.trim(),
      telefone: telefone || "",
      cliente_id: null,
      data_prevista: dataPrevista || null,
      created_at: now,
    };

    const movData = {
      id: movId,
      devedor_id: devId,
      tipo: "divida",
      valor: parseFloat(valor),
      obs: "Cadastro inicial de dívida",
      data: dataOperacao,
      user_id: req.user?.id || null,
    };

    db.prepare(`
      INSERT INTO devedores (id, nome, telefone, cliente_id, data_prevista, created_at)
      VALUES (?, ?, ?, NULL, ?, ?)
    `).run(devId, devedorData.nome, devedorData.telefone, devedorData.data_prevista, now);

    db.prepare(`
      INSERT INTO movimentos_devedor (id, devedor_id, tipo, valor, obs, data, user_id)
      VALUES (?, ?, 'divida', ?, 'Cadastro inicial de dívida', ?, ?)
    `).run(movId, devId, movData.valor, dataOperacao, movData.user_id);

    FirestoreSyncService.saveDevedor(devedorData, movData);

    res.json({ success: true, id: devId });
  } catch (err: any) {
    res.status(500).json({ error: "Erro ao cadastrar devedor." });
  }
});

app.post("/api/devedores/:id/movimento", authMiddleware, requireRole(["admin", "gerente", "caixa"]), async (req: AuthRequest, res: Response) => {
  try {
    const devedorId = parseInt(req.params.id);
    const { tipo, valor, obs } = req.body;

    if (!["divida", "pagamento"].includes(tipo) || !valor || parseFloat(valor) <= 0) {
      res.status(400).json({ error: "Tipo ('divida' ou 'pagamento') e valor positivo são obrigatórios." });
      return;
    }

    const movId = await getNextSequence("movimentos_devedor");
    const now = new Date().toISOString();

    const movData = {
      id: movId,
      devedor_id: devedorId,
      tipo,
      valor: parseFloat(valor),
      obs: obs || "",
      data: now,
      user_id: req.user?.id || null,
    };

    db.prepare(`
      INSERT INTO movimentos_devedor (id, devedor_id, tipo, valor, obs, data, user_id)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(movId, devedorId, tipo, movData.valor, movData.obs, now, movData.user_id);

    FirestoreSyncService.saveMovimentoDevedor(movData);

    res.json({ success: true, message: "Movimentação registrada com sucesso na nuvem." });
  } catch (err: any) {
    res.status(500).json({ error: "Erro ao registrar movimento." });
  }
});

/* ========================================================================== */
/*                               API: VENDEDORES & COMISSÕES                  */
/* ========================================================================== */

app.get("/api/vendedores", authMiddleware, (req: AuthRequest, res: Response) => {
  try {
    const vendedores = db.prepare("SELECT * FROM vendedores ORDER BY nome ASC").all();
    res.json(vendedores);
  } catch (err: any) {
    res.status(500).json({ error: "Erro ao carregar vendedores." });
  }
});

app.post("/api/vendedores", authMiddleware, requireRole(["admin", "gerente"]), async (req: AuthRequest, res: Response) => {
  try {
    const { nome, comissao_percentual, ativo } = req.body;
    if (!nome) {
      res.status(400).json({ error: "Nome do vendedor é obrigatório." });
      return;
    }
    const newId = await getNextSequence("vendedores");
    const now = new Date().toISOString();

    const venData = {
      id: newId,
      nome: nome.trim(),
      comissao_percentual: parseFloat(comissao_percentual) || 0,
      ativo: ativo ? 1 : 0,
      user_id: null,
      created_at: now,
    };

    db.prepare(`
      INSERT INTO vendedores (id, nome, comissao_percentual, ativo, created_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(newId, venData.nome, venData.comissao_percentual, venData.ativo, now);

    FirestoreSyncService.saveVendedor(venData);

    res.json({ success: true, id: newId });
  } catch (err: any) {
    res.status(500).json({ error: "Erro ao salvar vendedor." });
  }
});

app.put("/api/vendedores/:id", authMiddleware, requireRole(["admin", "gerente"]), (req: AuthRequest, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const { nome, comissao_percentual, ativo } = req.body;

    const existing = db.prepare("SELECT * FROM vendedores WHERE id = ?").get(id) as any;
    if (!existing) {
      res.status(404).json({ error: "Vendedor não encontrado." });
      return;
    }

    const updated = {
      ...existing,
      nome: nome.trim(),
      comissao_percentual: parseFloat(comissao_percentual) || 0,
      ativo: ativo ? 1 : 0,
    };

    db.prepare(`
      UPDATE vendedores SET nome = ?, comissao_percentual = ?, ativo = ? WHERE id = ?
    `).run(updated.nome, updated.comissao_percentual, updated.ativo, id);

    FirestoreSyncService.saveVendedor(updated);

    res.json({ success: true, message: "Vendedor atualizado na nuvem." });
  } catch (err: any) {
    res.status(500).json({ error: "Erro ao atualizar vendedor." });
  }
});

app.delete("/api/vendedores/:id", authMiddleware, requireRole(["admin", "gerente"]), (req: AuthRequest, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    db.prepare("DELETE FROM vendedores WHERE id = ?").run(id);
    FirestoreSyncService.deleteVendedor(id);
    res.json({ success: true, message: "Vendedor excluído." });
  } catch (err: any) {
    res.status(500).json({ error: "Erro ao excluir vendedor." });
  }
});

app.get("/api/comissoes", authMiddleware, requireRole(["admin", "gerente", "vendedor"]), (req: AuthRequest, res: Response) => {
  try {
    const { de, ate } = req.query;
    let filter = "WHERE 1=1";
    const params: any[] = [];

    if (de) {
      filter += " AND DATE(v.data) >= DATE(?)";
      params.push(de);
    }
    if (ate) {
      filter += " AND DATE(v.data) <= DATE(?)";
      params.push(ate);
    }

    const vendedores = db.prepare("SELECT * FROM vendedores").all() as any[];
    const vendas = db.prepare(`SELECT * FROM vendas v ${filter}`).all(...params) as any[];

    let linhas = vendedores.map((ven) => {
      const vendasDoVendedor = vendas.filter((v) => v.vendedor_id === ven.id);
      const totalVendido = vendasDoVendedor.reduce((s, v) => s + v.total, 0);
      const taxa = ven.comissao_percentual || 0;
      const comissao = totalVendido * (taxa / 100);

      return {
        id: ven.id,
        nome: ven.nome,
        qtdVendas: vendasDoVendedor.length,
        totalVendido,
        comissaoPercentual: taxa,
        comissaoAPagar: comissao,
      };
    });

    const semVendedor = vendas.filter((v) => !v.vendedor_id);
    if (semVendedor.length > 0 && req.user?.role !== "vendedor") {
      linhas.push({
        id: 0,
        nome: "(Sem vendedor vinculado)",
        qtdVendas: semVendedor.length,
        totalVendido: semVendedor.reduce((s, v) => s + v.total, 0),
        comissaoPercentual: 0,
        comissaoAPagar: 0,
      });
    }

    if (req.user?.role === "vendedor") {
      const primeiroNome = req.user.nome.split(" ")[0].toLowerCase();
      const minhaLinha = linhas.filter((l) => l.nome.toLowerCase().includes(primeiroNome));
      if (minhaLinha.length > 0) {
        linhas = minhaLinha;
      }
    }

    const totalGeralComissoes = linhas.reduce((s, l) => s + l.comissaoAPagar, 0);
    const totalGeralVendas = linhas.reduce((s, l) => s + l.totalVendido, 0);

    res.json({
      linhas,
      totalGeralComissoes,
      totalGeralVendas,
    });
  } catch (err: any) {
    res.status(500).json({ error: "Erro ao gerar comissões." });
  }
});

/* ========================================================================== */
/*                               API: DASHBOARD & RELATÓRIOS                  */
/* ========================================================================== */

app.get("/api/relatorios/dashboard", authMiddleware, (req: AuthRequest, res: Response) => {
  try {
    const produtos = db.prepare("SELECT id, estoque, custo, minimo FROM produtos").all() as any[];
    const qtdProdutos = produtos.length;
    const valorEstoque = produtos.reduce((s, p) => s + (p.estoque * p.custo), 0);
    const estoqueBaixo = produtos.filter((p) => p.estoque <= p.minimo).length;

    // Debtors
    const devedoresRes = db.prepare(`
      SELECT
        COALESCE(SUM(CASE WHEN tipo = 'divida' THEN valor ELSE 0 END), 0) -
        COALESCE(SUM(CASE WHEN tipo = 'pagamento' THEN valor ELSE 0 END), 0) as total_receber
      FROM movimentos_devedor
    `).get() as any;
    const valorReceber = Math.max(0, devedoresRes ? devedoresRes.total_receber : 0);

    const devedoresPendentes = db.prepare(`
      SELECT d.id
      FROM devedores d
      JOIN movimentos_devedor m ON d.id = m.devedor_id
      GROUP BY d.id
      HAVING (SUM(CASE WHEN m.tipo = 'divida' THEN m.valor ELSE 0 END) - SUM(CASE WHEN m.tipo = 'pagamento' THEN m.valor ELSE 0 END)) > 0.01
    `).all() as any[];

    // Sales today & this month
    const hojeStr = new Date().toISOString().slice(0, 10);
    const inicioMesStr = new Date(new Date().getFullYear(), new Date().getMonth(), 1).toISOString().slice(0, 10);

    const vendasHojeRes = db.prepare(`
      SELECT COALESCE(SUM(total), 0) as total FROM vendas WHERE DATE(data) = DATE(?)
    `).get(hojeStr) as any;

    const vendasMesRes = db.prepare(`
      SELECT COALESCE(SUM(total), 0) as total, COALESCE(SUM(lucro), 0) as lucro
      FROM vendas WHERE DATE(data) >= DATE(?)
    `).get(inicioMesStr) as any;

    // Recent 6 sales
    const ultimasVendas = db.prepare(`
      SELECT v.id, v.data, v.total, v.forma_pagamento, c.nome as cliente_nome
      FROM vendas v
      LEFT JOIN clientes c ON v.cliente_id = c.id
      ORDER BY v.data DESC
      LIMIT 6
    `).all() as any[];

    const getItens = db.prepare("SELECT nome, qtd FROM itens_venda WHERE venda_id = ?");
    ultimasVendas.forEach((v) => {
      v.itens = getItens.all(v.id);
    });

    // Daily breakdown for current month
    const now = new Date();
    const diasNoMes = new Date(now.getFullYear(), now.getMonth() + 1, 0).getDate();
    const vendasMes = db.prepare(`
      SELECT data, total FROM vendas WHERE DATE(data) >= DATE(?)
    `).all(inicioMesStr) as any[];

    const totaisPorDia = Array(diasNoMes).fill(0);
    vendasMes.forEach((v) => {
      const dia = new Date(v.data).getDate();
      if (dia >= 1 && dia <= diasNoMes) {
        totaisPorDia[dia - 1] += v.total;
      }
    });

    res.json({
      qtdProdutos,
      valorEstoque,
      estoqueBaixo,
      qtdDevedores: devedoresPendentes.length,
      valorReceber,
      vendidoHoje: vendasHojeRes.total,
      vendidoMes: vendasMesRes.total,
      lucroMes: vendasMesRes.lucro,
      ultimasVendas,
      graficoDias: {
        dias: Array.from({ length: diasNoMes }, (_, i) => i + 1),
        valores: totaisPorDia,
      },
    });
  } catch (err: any) {
    res.status(500).json({ error: "Erro ao gerar métricas do dashboard: " + err.message });
  }
});

// Detailed Monthly Performance Reports
app.get("/api/relatorios/mensal", authMiddleware, requireRole(["admin", "gerente"]), (req: AuthRequest, res: Response) => {
  try {
    const ano = parseInt(req.query.ano as string) || new Date().getFullYear();
    const mes = parseInt(req.query.mes as string) || (new Date().getMonth() + 1); // 1-12

    const mesFormatado = mes < 10 ? `0${mes}` : `${mes}`;
    const inicioMes = `${ano}-${mesFormatado}-01`;
    const diasNoMes = new Date(ano, mes, 0).getDate();
    const fimMes = `${ano}-${mesFormatado}-${diasNoMes < 10 ? '0' + diasNoMes : diasNoMes}`;

    const vendas = db.prepare(`
      SELECT v.*, c.nome as cliente_nome, ven.nome as vendedor_nome, ven.comissao_percentual
      FROM vendas v
      LEFT JOIN clientes c ON v.cliente_id = c.id
      LEFT JOIN vendedores ven ON v.vendedor_id = ven.id
      WHERE DATE(v.data) >= DATE(?) AND DATE(v.data) <= DATE(?)
      ORDER BY v.data ASC
    `).all(inicioMes, fimMes) as any[];

    const getItens = db.prepare(`
      SELECT iv.*, p.categoria, p.marca
      FROM itens_venda iv
      LEFT JOIN produtos p ON iv.produto_id = p.id
      WHERE iv.venda_id = ?
    `);

    const todosItens: any[] = [];
    vendas.forEach((v) => {
      v.itens = getItens.all(v.id);
      v.itens.forEach((it: any) => todosItens.push(it));
    });

    const faturamentoBruto = vendas.reduce((s, v) => s + v.total, 0);
    const subtotalBruto = vendas.reduce((s, v) => s + v.subtotal, 0);
    const totalDescontos = vendas.reduce((s, v) => s + v.desconto, 0);
    const lucroBruto = vendas.reduce((s, v) => s + v.lucro, 0);
    const cmv = faturamentoBruto - lucroBruto;
    const margemPercentual = faturamentoBruto > 0 ? (lucroBruto / faturamentoBruto) * 100 : 0;
    const qtdVendas = vendas.length;
    const ticketMedio = qtdVendas > 0 ? faturamentoBruto / qtdVendas : 0;

    const formasPagamentoMap: Record<string, { qtd: number; total: number }> = {};
    ["Dinheiro", "PIX", "Cartão", "Fiado"].forEach((f) => {
      formasPagamentoMap[f] = { qtd: 0, total: 0 };
    });

    vendas.forEach((v) => {
      const f = v.forma_pagamento || "Outro";
      if (!formasPagamentoMap[f]) formasPagamentoMap[f] = { qtd: 0, total: 0 };
      formasPagamentoMap[f].qtd += 1;
      formasPagamentoMap[f].total += v.total;
    });

    const formasPagamento = Object.keys(formasPagamentoMap).map((forma) => ({
      forma,
      qtd: formasPagamentoMap[forma].qtd,
      total: formasPagamentoMap[forma].total,
      percentual: faturamentoBruto > 0 ? (formasPagamentoMap[forma].total / faturamentoBruto) * 100 : 0,
    }));

    const vendedoresCadastrados = db.prepare("SELECT id, nome, comissao_percentual FROM vendedores").all() as any[];
    const vendedoresMap: Record<string, { nome: string; qtd: number; total: number; comissaoTaxa: number; comissaoTotal: number }> = {};

    vendedoresCadastrados.forEach((ven) => {
      vendedoresMap[String(ven.id)] = {
        nome: ven.nome,
        qtd: 0,
        total: 0,
        comissaoTaxa: ven.comissao_percentual || 0,
        comissaoTotal: 0,
      };
    });

    vendedoresMap["sem_vendedor"] = {
      nome: "(Sem vendedor)",
      qtd: 0,
      total: 0,
      comissaoTaxa: 0,
      comissaoTotal: 0,
    };

    vendas.forEach((v) => {
      const key = v.vendedor_id ? String(v.vendedor_id) : "sem_vendedor";
      if (!vendedoresMap[key]) {
        vendedoresMap[key] = {
          nome: v.vendedor_nome || `Vendedor #${v.vendedor_id}`,
          qtd: 0,
          total: 0,
          comissaoTaxa: v.comissao_percentual || 0,
          comissaoTotal: 0,
        };
      }
      vendedoresMap[key].qtd += 1;
      vendedoresMap[key].total += v.total;
      vendedoresMap[key].comissaoTotal += v.total * (vendedoresMap[key].comissaoTaxa / 100);
    });

    const rankingVendedores = Object.values(vendedoresMap)
      .filter((ven) => ven.qtd > 0 || ven.nome !== "(Sem vendedor)")
      .map((ven) => ({
        ...ven,
        participacao: faturamentoBruto > 0 ? (ven.total / faturamentoBruto) * 100 : 0,
        ticketMedio: ven.qtd > 0 ? ven.total / ven.qtd : 0,
      }))
      .sort((a, b) => b.total - a.total);

    const produtosMap: Record<number, { nome: string; marca: string; categoria: string; qtd: number; faturamento: number; custo: number; lucro: number }> = {};

    todosItens.forEach((it) => {
      const pId = it.produto_id;
      if (!produtosMap[pId]) {
        produtosMap[pId] = {
          nome: it.nome,
          marca: it.marca || "-",
          categoria: it.categoria || "Geral",
          qtd: 0,
          faturamento: 0,
          custo: 0,
          lucro: 0,
        };
      }
      const itemFaturamento = it.qtd * it.preco_unit;
      const itemCusto = it.qtd * (it.custo_unit || 0);
      produtosMap[pId].qtd += it.qtd;
      produtosMap[pId].faturamento += itemFaturamento;
      produtosMap[pId].custo += itemCusto;
      produtosMap[pId].lucro += (itemFaturamento - itemCusto);
    });

    const topProdutos = Object.values(produtosMap)
      .map((p) => ({
        ...p,
        margemPercentual: p.faturamento > 0 ? (p.lucro / p.faturamento) * 100 : 0,
      }))
      .sort((a, b) => b.faturamento - a.faturamento);

    const categoriasMap: Record<string, { categoria: string; qtd: number; faturamento: number; lucro: number }> = {};
    topProdutos.forEach((p) => {
      const cat = p.categoria || "Outros";
      if (!categoriasMap[cat]) {
        categoriasMap[cat] = { categoria: cat, qtd: 0, faturamento: 0, lucro: 0 };
      }
      categoriasMap[cat].qtd += p.qtd;
      categoriasMap[cat].faturamento += p.faturamento;
      categoriasMap[cat].lucro += p.lucro;
    });

    const desempenhoCategorias = Object.values(categoriasMap).sort((a, b) => b.faturamento - a.faturamento);

    const evolucaoDiaria = Array.from({ length: diasNoMes }, (_, idx) => {
      const diaNum = idx + 1;
      const diaStr = diaNum < 10 ? `0${diaNum}` : `${diaNum}`;
      const dataIso = `${ano}-${mesFormatado}-${diaStr}`;
      const vendasDoDia = vendas.filter((v) => v.data.slice(0, 10) === dataIso);
      const totalDia = vendasDoDia.reduce((s, v) => s + v.total, 0);
      const lucroDia = vendasDoDia.reduce((s, v) => s + v.lucro, 0);

      return {
        dia: diaNum,
        data: dataIso,
        qtdVendas: vendasDoDia.length,
        faturamento: totalDia,
        lucro: lucroDia,
      };
    });

    res.json({
      periodo: {
        ano,
        mes,
        mesNome: new Date(ano, mes - 1, 1).toLocaleDateString("pt-BR", { month: "long" }),
        inicio: inicioMes,
        fim: fimMes,
      },
      kpis: {
        faturamentoBruto,
        subtotalBruto,
        totalDescontos,
        cmv,
        lucroBruto,
        margemPercentual,
        qtdVendas,
        ticketMedio,
      },
      formasPagamento,
      rankingVendedores,
      topProdutos,
      desempenhoCategorias,
      evolucaoDiaria,
    });
  } catch (err: any) {
    res.status(500).json({ error: "Erro ao gerar relatório mensal detalhado: " + err.message });
  }
});

/* ========================================================================== */
/*                               API: BACKUP & RESTAURAÇÃO                    */
/* ========================================================================== */

app.get("/api/backup/export", authMiddleware, requireRole(["admin"]), (req: AuthRequest, res: Response) => {
  try {
    const backup = {
      versao: "2.0.0",
      exportadoEm: new Date().toISOString(),
      config: db.prepare("SELECT * FROM config").all(),
      users: db.prepare("SELECT id, username, nome, email, password_hash, salt, role, ativo, created_at FROM users").all(),
      vendedores: db.prepare("SELECT * FROM vendedores").all(),
      produtos: db.prepare("SELECT * FROM produtos").all(),
      movimentacoes: db.prepare("SELECT * FROM movimentacoes").all(),
      clientes: db.prepare("SELECT * FROM clientes").all(),
      vendas: db.prepare("SELECT * FROM vendas").all(),
      itens_venda: db.prepare("SELECT * FROM itens_venda").all(),
      devedores: db.prepare("SELECT * FROM devedores").all(),
      movimentos_devedor: db.prepare("SELECT * FROM movimentos_devedor").all(),
    };
    res.json(backup);
  } catch (err: any) {
    res.status(500).json({ error: "Erro ao exportar backup." });
  }
});

app.post("/api/backup/import", authMiddleware, requireRole(["admin"]), async (req: AuthRequest, res: Response) => {
  try {
    const data = req.body;
    if (!data || !Array.isArray(data.produtos)) {
      res.status(400).json({ error: "Estrutura de arquivo de backup inválida." });
      return;
    }

    // Clear data in local cache
    db.prepare("DELETE FROM movimentacoes").run();
    db.prepare("DELETE FROM itens_venda").run();
    db.prepare("DELETE FROM vendas").run();
    db.prepare("DELETE FROM movimentos_devedor").run();
    db.prepare("DELETE FROM devedores").run();
    db.prepare("DELETE FROM clientes").run();
    db.prepare("DELETE FROM produtos").run();
    db.prepare("DELETE FROM vendedores").run();

    // Restore products
    const insertProd = db.prepare(`
      INSERT INTO produtos (id, nome, marca, categoria, sabor, peso, codigo_interno, codigo_barras, custo, venda, estoque, minimo, foto, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    for (const p of data.produtos) {
      insertProd.run(
        p.id, p.nome, p.marca || "", p.categoria || "", p.sabor || "", p.peso || "",
        p.codigo_interno || p.codigoInterno || "", p.codigo_barras || p.codigoBarras || "",
        p.custo || 0, p.venda || 0, p.estoque || 0, p.minimo || 5, p.foto || "",
        p.created_at || new Date().toISOString(), p.updated_at || new Date().toISOString()
      );
    }

    // Restore clients
    if (Array.isArray(data.clientes)) {
      const insertCli = db.prepare(`
        INSERT INTO clientes (id, nome, telefone, whatsapp, created_at)
        VALUES (?, ?, ?, ?, ?)
      `);
      for (const c of data.clientes) {
        insertCli.run(c.id, c.nome, c.telefone || "", c.whatsapp || "", c.created_at || new Date().toISOString());
      }
    }

    // Restore sellers
    if (Array.isArray(data.vendedores)) {
      const insertVen = db.prepare(`
        INSERT INTO vendedores (id, nome, comissao_percentual, ativo, user_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `);
      for (const v of data.vendedores) {
        insertVen.run(v.id, v.nome, v.comissao_percentual || v.comissaoPercentual || 0, v.ativo !== undefined ? (v.ativo ? 1 : 0) : 1, v.user_id || null, v.created_at || new Date().toISOString());
      }
    }

    // Restore sales & items
    if (Array.isArray(data.vendas)) {
      const insertVenda = db.prepare(`
        INSERT INTO vendas (id, data, cliente_id, vendedor_id, subtotal, desconto, total, lucro, forma_pagamento, data_prevista, user_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      for (const v of data.vendas) {
        insertVenda.run(
          v.id, v.data, v.cliente_id || v.clienteId || null, v.vendedor_id || v.vendedorId || null,
          v.subtotal || 0, v.desconto || 0, v.total || 0, v.lucro || 0, v.forma_pagamento || v.formaPagamento || "Dinheiro",
          v.data_prevista || v.dataPrevista || null, v.user_id || null, v.created_at || v.data
        );
      }
    }

    if (Array.isArray(data.itens_venda)) {
      const insertItem = db.prepare(`
        INSERT INTO itens_venda (id, venda_id, produto_id, nome, qtd, preco_unit, custo_unit, subtotal)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `);
      for (const it of data.itens_venda) {
        insertItem.run(it.id, it.venda_id || it.vendaId, it.produto_id || it.produtoId, it.nome, it.qtd, it.preco_unit || it.precoUnit, it.custo_unit || it.custoUnit, it.subtotal || (it.qtd * it.preco_unit));
      }
    }

    // Restore debtors
    if (Array.isArray(data.devedores)) {
      const insertDev = db.prepare(`
        INSERT INTO devedores (id, nome, telefone, cliente_id, data_prevista, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `);
      for (const d of data.devedores) {
        insertDev.run(d.id, d.nome, d.telefone || "", d.cliente_id || d.clienteId || null, d.data_prevista || d.dataPrevista || null, d.created_at || new Date().toISOString());
      }
    }

    if (Array.isArray(data.movimentos_devedor)) {
      const insertMovDev = db.prepare(`
        INSERT INTO movimentos_devedor (id, devedor_id, tipo, valor, obs, data, user_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `);
      for (const m of data.movimentos_devedor) {
        insertMovDev.run(m.id, m.devedor_id || m.devedorId, m.tipo, m.valor, m.obs || "", m.data, m.user_id || null);
      }
    }

    // Sync cloud database
    await FirestoreSyncService.restoreFullCloudBackup(data);

    res.json({ success: true, message: "Backup restaurado com sucesso no banco de dados em nuvem." });
  } catch (err: any) {
    res.status(500).json({ error: "Erro ao restaurar backup: " + err.message });
  }
});

/* ========================================================================== */
/*                               API FALLBACK & ERROS                         */
/* ========================================================================== */

app.all("/api/*", (req: Request, res: Response) => {
  res.status(404).json({ error: `Rota de API não encontrada: ${req.method} ${req.path}` });
});

app.use("/api", (err: any, req: Request, res: Response, next: NextFunction) => {
  console.error("[API Error]", err);
  res.status(err.status || 500).json({ error: err.message || "Erro interno do servidor." });
});

/* ========================================================================== */
/*                               VITE MIDDLEWARE                              */
/* ========================================================================== */

async function start() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req: Request, res: Response) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`[AppVenda] Servidor operacional com Firestore em http://localhost:${PORT}`);
  });
}

start();
