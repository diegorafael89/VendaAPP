// AppVenda - Client Engine
// Connects UI to secure Express/SQLite API with RBAC, period filters, and monthly performance reports.
import * as XLSX from "xlsx";
import {
  subscribeToProducts,
  subscribeToInventoryMovements,
  onRealtimeStatusChange,
  ProductItem,
  InventoryMovementItem,
} from "./firebase-client";

declare const bootstrap: any;
declare const Chart: any;
declare const Swal: any;

interface CurrentUser {
  id: number;
  username: string;
  nome: string;
  email: string;
  role: "admin" | "gerente" | "caixa" | "vendedor";
}

let currentUser: CurrentUser | null = null;
let policies = { ocultarVendasVendedor: false };
let produtos: any[] = [];
let produtosImportacaoExcel: any[] = [];
let movimentacoes: any[] = [];
let clientes: any[] = [];
let vendedores: any[] = [];
let devedores: any[] = [];
let carrinho: any[] = [];
let filtroPendentes = false;
let relatorioAtivo = "mensal";

// Realtime subscriptions
let unsubscribeProducts: (() => void) | null = null;
let unsubscribeInventory: (() => void) | null = null;

// Chart instances to prevent canvas reuse errors
let chartVendasMesInstance: any = null;
let chartRelMensalEvolucaoInstance: any = null;
let chartRelMensalFormasInstance: any = null;

const TOKEN_KEY = "appvenda_token";

/* ========================================================================== */
/*                               API HELPER                                   */
/* ========================================================================== */

async function apiFetch(endpoint: string, options: RequestInit = {}) {
  const token = localStorage.getItem(TOKEN_KEY);
  const headers = new Headers(options.headers || {});
  if (!headers.has("Accept")) {
    headers.set("Accept", "application/json");
  }
  if (!headers.has("Content-Type") && !(options.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
  }
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  const isPublic = endpoint.startsWith("/api/auth/login") || endpoint === "/api/config" || endpoint === "/api/health";
  if (!token && !isPublic) {
    mostrarModalLogin();
    throw new Error("Sessão expirada. Faça login novamente.");
  }

  let res: Response;
  try {
    res = await fetch(endpoint, { ...options, headers });
  } catch (netErr: any) {
    throw new Error("Não foi possível conectar ao servidor. Verifique a conexão.");
  }
  
  if (res.status === 401) {
    localStorage.removeItem(TOKEN_KEY);
    currentUser = null;
    mostrarModalLogin();
    throw new Error("Sessão expirada. Faça login novamente.");
  }

  const contentType = res.headers.get("content-type") || "";
  let data: any = null;

  if (contentType.includes("application/json")) {
    try {
      data = await res.json();
    } catch {
      data = null;
    }
  } else {
    await res.text().catch(() => "");
    if (!res.ok) {
      throw new Error(`Serviço temporariamente indisponível (${res.status}). Aguarde um instante.`);
    }
    throw new Error("Resposta do servidor não está em formato JSON válido.");
  }

  if (!res.ok) {
    throw new Error(data?.error || `Erro na requisição: ${res.statusText}`);
  }
  return data;
}

function brl(v: number): string {
  return (v || 0).toLocaleString("pt-BR", { style: "currency", currency: "BRL" });
}

function fmtData(iso: string): string {
  if (!iso) return "-";
  const d = new Date(iso);
  return d.toLocaleDateString("pt-BR");
}

function fmtDataHora(iso: string): string {
  if (!iso) return "-";
  const d = new Date(iso);
  return `${d.toLocaleDateString("pt-BR")} ${d.toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" })}`;
}

function toast(msg: string, icon: "success" | "error" | "warning" | "info" = "success") {
  const surfaceColor = getComputedStyle(document.body).getPropertyValue("--surface") || "#171e24";
  const textColor = getComputedStyle(document.body).getPropertyValue("--text") || "#e8edf1";
  Swal.fire({
    toast: true,
    position: "bottom",
    icon,
    title: msg,
    showConfirmButton: false,
    timer: 2000,
    background: surfaceColor,
    color: textColor,
  });
}

/* ========================================================================== */
/*                               AUTENTICAÇÃO & ROLES                         */
/* ========================================================================== */

function mostrarModalLogin() {
  const modalEl = document.getElementById("modalLogin");
  if (modalEl) {
    const m = bootstrap.Modal.getOrCreateInstance(modalEl);
    m.show();
  }
}

function esconderModalLogin() {
  const modalEl = document.getElementById("modalLogin");
  if (modalEl) {
    const m = bootstrap.Modal.getInstance(modalEl);
    if (m) m.hide();
  }
}

async function verificarSessao() {
  const token = localStorage.getItem(TOKEN_KEY);
  if (!token) {
    mostrarModalLogin();
    return;
  }

  try {
    const res = await apiFetch("/api/auth/me");
    currentUser = res.user;
    policies = res.policies || { ocultarVendasVendedor: false };
    aplicarPerfilUsuario();
    carregarTudo();
    if (currentUser?.role === "vendedor" || currentUser?.role === "caixa") {
      navegarParaTab("vendas");
    }
  } catch (err) {
    mostrarModalLogin();
  }
}

async function executarLogin(e: Event) {
  e.preventDefault();
  const identifier = (document.getElementById("loginIdentifier") as HTMLInputElement).value.trim();
  const password = (document.getElementById("loginPassword") as HTMLInputElement).value.trim();

  if (!identifier || !password) {
    toast("Informe usuário e senha", "warning");
    return;
  }

  const btn = document.getElementById("btnLoginSubmit") as HTMLButtonElement;
  btn.disabled = true;
  btn.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span> Autenticando...`;

  try {
    const res = await apiFetch("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ identifier, password }),
    });

    localStorage.setItem(TOKEN_KEY, res.token);
    currentUser = res.user;
    policies = res.policies || { ocultarVendasVendedor: false };

    esconderModalLogin();
    toast(`Bem-vindo, ${currentUser?.nome}!`, "success");
    aplicarPerfilUsuario();
    carregarTudo();
    if (currentUser?.role === "vendedor" || currentUser?.role === "caixa") {
      navegarParaTab("vendas");
    }
  } catch (err: any) {
    toast(err.message || "Falha no login", "error");
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<i class="fa-solid fa-right-to-bracket me-1"></i> Entrar no Sistema`;
  }
}

function preencherLogin(u: string, p: string) {
  const uEl = document.getElementById("loginIdentifier") as HTMLInputElement;
  const pEl = document.getElementById("loginPassword") as HTMLInputElement;
  if (uEl) uEl.value = u;
  if (pEl) pEl.value = p;
}

function preencherELogar(u: string, p: string) {
  preencherLogin(u, p);
  const btn = document.getElementById("btnLoginSubmit") as HTMLButtonElement;
  if (btn) btn.click();
}

function toggleMostrarSenhaLogin() {
  const pEl = document.getElementById("loginPassword") as HTMLInputElement;
  const icon = document.getElementById("iconOlhoSenha");
  const btnIcon = document.getElementById("btnEyeIcon");
  const text = document.getElementById("textOlhoSenha");
  if (!pEl) return;

  if (pEl.type === "password") {
    pEl.type = "text";
    if (icon) icon.className = "fa-solid fa-eye-slash";
    if (btnIcon) btnIcon.className = "fa-solid fa-eye-slash";
    if (text) text.textContent = "Ocultar";
  } else {
    pEl.type = "password";
    if (icon) icon.className = "fa-solid fa-eye";
    if (btnIcon) btnIcon.className = "fa-solid fa-eye";
    if (text) text.textContent = "Mostrar";
  }
}

async function restaurarCredenciaisPadrao() {
  try {
    const res = await apiFetch("/api/auth/reset-defaults", { method: "POST" });
    toast(res.message || "Credenciais padrão restauradas!", "success");
    preencherLogin("admin", "admin123");
  } catch (err: any) {
    toast(err.message || "Erro ao restaurar credenciais", "error");
  }
}

async function logoutUsuario() {
  if (unsubscribeProducts) {
    unsubscribeProducts();
    unsubscribeProducts = null;
  }
  if (unsubscribeInventory) {
    unsubscribeInventory();
    unsubscribeInventory = null;
  }
  try {
    await apiFetch("/api/auth/logout", { method: "POST" });
  } catch (e) {}
  localStorage.removeItem(TOKEN_KEY);
  currentUser = null;
  toast("Sessão finalizada");
  mostrarModalLogin();
}

function openUserMenuModal() {
  if (!currentUser) {
    mostrarModalLogin();
    return;
  }
  Swal.fire({
    title: currentUser.nome,
    html: `
      <p class="mb-1"><strong>Login:</strong> ${currentUser.username}</p>
      <p class="mb-1"><strong>E-mail:</strong> ${currentUser.email}</p>
      <p class="mb-3"><strong>Função:</strong> <span class="badge role-${currentUser.role}">${currentUser.role.toUpperCase()}</span></p>
      <div class="alert alert-info py-2" style="font-size:12px;">
        ${currentUser.role === 'vendedor' && policies.ocultarVendasVendedor ? 'Seu perfil de Vendedor possui restrição de acesso à tela de Vendas PDV.' : 'Acesso liberado de acordo com seu perfil de permissões.'}
      </div>
    `,
    showCancelButton: true,
    confirmButtonText: '<i class="fa-solid fa-arrow-right-from-bracket me-1"></i> Desconectar',
    cancelButtonText: 'Fechar',
    confirmButtonColor: '#e05a4e',
  }).then((r: any) => {
    if (r.isConfirmed) {
      logoutUsuario();
    }
  });
}

function aplicarPerfilUsuario() {
  if (!currentUser) return;

  const role = currentUser.role;
  const isVendedor = role === "vendedor";
  const isAdmin = role === "admin";
  const isGerente = role === "gerente";

  // Topbar info
  const nameEl = document.getElementById("topbarUserName");
  const roleEl = document.getElementById("topbarUserRole");
  if (nameEl) nameEl.textContent = currentUser.nome;
  if (roleEl) {
    roleEl.textContent = role.toUpperCase();
    roleEl.className = `badge-role role-${role}`;
  }

  // Vendedor e Operador de Caixa têm acesso completo ao PDV de Vendas
  const navVendas = document.getElementById("nav-vendas");
  const bannerVendedor = document.getElementById("bannerVendedorOculto");

  if (navVendas) {
    navVendas.style.display = "flex";
  }

  if (bannerVendedor) {
    bannerVendedor.classList.add("d-none");
  }

  // Controle de visibilidade das abas para papéis
  const navDashboard = document.getElementById("nav-dashboard");
  const navEstoque = document.getElementById("nav-estoque");
  const navDevedores = document.getElementById("nav-devedores");
  const navRelatorios = document.getElementById("nav-relatorios");
  const navComissoes = document.getElementById("nav-comissoes");
  const navUsuarios = document.getElementById("nav-usuarios");
  const navConfig = document.getElementById("nav-config");
  const adminDivider = document.getElementById("adminDivider");

  if (isVendedor || role === "caixa") {
    if (navDashboard) navDashboard.style.display = "none";
    if (navEstoque) navEstoque.style.display = "none";
    if (navVendas) navVendas.style.display = "flex";
    if (navDevedores) navDevedores.style.display = "flex";
    if (navRelatorios) navRelatorios.style.display = "none";
    if (navUsuarios) navUsuarios.style.display = "none";
    if (navConfig) navConfig.style.display = "none";
    if (adminDivider) adminDivider.style.display = "none";
    if (navComissoes) navComissoes.style.display = "none"; // Sem tela de comissões para vendedor
  } else if (isGerente) {
    if (navDashboard) navDashboard.style.display = "flex";
    if (navEstoque) navEstoque.style.display = "flex";
    if (navVendas) navVendas.style.display = "flex";
    if (navDevedores) navDevedores.style.display = "flex";
    if (navRelatorios) navRelatorios.style.display = "flex";
    if (navComissoes) navComissoes.style.display = "flex";
    if (navUsuarios) navUsuarios.style.display = "none";
    if (navConfig) navConfig.style.display = "none";
    if (adminDivider) adminDivider.style.display = "none";
  } else if (isAdmin) {
    if (navDashboard) navDashboard.style.display = "flex";
    if (navEstoque) navEstoque.style.display = "flex";
    if (navVendas) navVendas.style.display = "flex";
    if (navDevedores) navDevedores.style.display = "flex";
    if (navRelatorios) navRelatorios.style.display = "flex";
    if (navComissoes) navComissoes.style.display = "flex";
    if (navUsuarios) navUsuarios.style.display = "flex";
    if (navConfig) navConfig.style.display = "flex";
    if (adminDivider) adminDivider.style.display = "block";
  }

  // Redireciona caso a aba ativa esteja oculta para o perfil atual ou seja dashboard para vendedor
  const tabAtivaAtual = document.querySelector(".sidebar .nav-link.active") as HTMLElement;
  if (!tabAtivaAtual || tabAtivaAtual.style.display === "none" || ((isVendedor || role === "caixa") && tabAtivaAtual.dataset.tab === "dashboard")) {
    if (isVendedor || role === "caixa") {
      navegarParaTab("vendas");
    } else {
      navegarParaTab("dashboard");
    }
  }
}

/* ========================================================================== */
/*                               NAVEGAÇÃO                                    */
/* ========================================================================== */

function navegarParaTab(tabName: string) {
  const isVendedor = currentUser?.role === "vendedor" || currentUser?.role === "caixa";
  if (tabName === "comissoes" && isVendedor) {
    tabName = "vendas";
  }

  document.querySelectorAll(".sidebar .nav-link").forEach((l) => l.classList.remove("active"));
  const link = document.querySelector(`.sidebar .nav-link[data-tab="${tabName}"]`);
  if (link) link.classList.add("active");

  document.querySelectorAll(".screen").forEach((s) => s.classList.remove("active"));
  const tela = document.getElementById(`tab-${tabName}`);
  if (tela) tela.classList.add("active");

  if (window.innerWidth <= 768) {
    document.getElementById("sidebar")?.classList.remove("show-mobile");
  }

  carregarAba(tabName);
}

function setupNavegacao() {
  document.querySelectorAll(".sidebar .nav-link").forEach((link) => {
    link.addEventListener("click", (e) => {
      e.preventDefault();
      const tab = (link as HTMLElement).dataset.tab;
      if (tab) navegarParaTab(tab);
    });
  });

  document.getElementById("btnToggleSidebar")?.addEventListener("click", () => {
    const sb = document.getElementById("sidebar");
    const cw = document.getElementById("contentWrap");
    if (window.innerWidth <= 768) {
      sb?.classList.toggle("show-mobile");
    } else {
      sb?.classList.toggle("collapsed");
      cw?.classList.toggle("expanded");
    }
  });

  document.getElementById("themeToggle")?.addEventListener("click", () => {
    const cur = document.documentElement.getAttribute("data-bs-theme");
    const next = cur === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-bs-theme", next);
    localStorage.setItem("appvenda_theme", next);
    atualizarIconeTema(next);
  });

  const savedTheme = localStorage.getItem("appvenda_theme") || "dark";
  document.documentElement.setAttribute("data-bs-theme", savedTheme);
  atualizarIconeTema(savedTheme);
}

function atualizarIconeTema(t: string) {
  const icon = document.getElementById("themeToggle");
  if (icon) {
    icon.className = t === "dark" ? "fa-solid fa-moon theme-switch" : "fa-solid fa-sun theme-switch";
  }
}

function carregarAba(tab: string) {
  switch (tab) {
    case "dashboard":
      carregarDashboard();
      break;
    case "produtos":
      carregarProdutos();
      break;
    case "estoque":
      carregarEstoque();
      break;
    case "vendas":
      carregarVendasFiltradas();
      break;
    case "clientes":
      carregarClientes();
      break;
    case "devedores":
      carregarDevedores();
      break;
    case "comissoes":
      carregarComissoes();
      break;
    case "relatorios":
      carregarRelatorioMensalDetalhado();
      break;
    case "usuarios":
      carregarUsuarios();
      break;
    case "config":
      carregarConfig();
      break;
  }
}

function iniciarSincronizacaoTempoReal() {
  if (unsubscribeProducts) unsubscribeProducts();
  if (unsubscribeInventory) unsubscribeInventory();

  // 1. Real-time Product Catalog Listener
  unsubscribeProducts = subscribeToProducts(
    (novosProdutos) => {
      produtos = novosProdutos;
      atualizarCategoriasSelect();
      renderProdutosFiltrados();
      popularSelectProdutosEstoque();
      renderEstoqueVisao();

      // Update Dashboard live counts
      const dQtd = document.getElementById("dQtdProdutos");
      if (dQtd) dQtd.textContent = String(produtos.length);
      const dEstoque = document.getElementById("dValorEstoque");
      if (dEstoque) {
        const valorTotal = produtos.reduce((s, p) => s + p.estoque * p.custo, 0);
        dEstoque.textContent = brl(valorTotal);
      }
      const dBaixo = document.getElementById("dEstoqueBaixo");
      if (dBaixo) {
        const baixos = produtos.filter((p) => p.estoque <= p.minimo).length;
        dBaixo.textContent = String(baixos);
      }

      // Update active cart item maximums if any
      carrinho.forEach((item) => {
        const prodAtual = produtos.find((p) => p.id === item.id);
        if (prodAtual) {
          item.estoqueMax = prodAtual.estoque;
        }
      });
    },
    (err) => {
      console.warn("[Realtime Client] Falha no listener de produtos, usando API fallback:", err);
    }
  );

  // 2. Real-time Inventory Movements Listener
  unsubscribeInventory = subscribeToInventoryMovements(
    (novasMovimentacoes) => {
      movimentacoes = novasMovimentacoes;
      renderHistoricoEstoqueFromList(novasMovimentacoes);
    },
    (err) => {
      console.warn("[Realtime Client] Falha no listener de estoque, usando API fallback:", err);
    }
  );
}

// Global connection badge updater
onRealtimeStatusChange((status, message) => {
  const badge = document.getElementById("topbarSyncBadge");
  const text = document.getElementById("topbarSyncText");
  if (!badge || !text) return;

  if (status === "connected") {
    badge.className = "badge bg-success-subtle text-success border border-success-subtle d-inline-flex align-items-center gap-1";
    text.textContent = "Firestore Tempo Real Ativo";
  } else if (status === "syncing") {
    badge.className = "badge bg-warning-subtle text-warning border border-warning-subtle d-inline-flex align-items-center gap-1";
    text.textContent = "Sincronizando...";
  } else if (status === "error") {
    badge.className = "badge bg-danger-subtle text-danger border border-danger-subtle d-inline-flex align-items-center gap-1";
    text.textContent = "Reconectando Firestore...";
  }
});

function carregarTudo() {
  carregarConfig();
  carregarProdutos();
  carregarClientes();
  carregarVendedores();
  iniciarSincronizacaoTempoReal();

  const linkAtivo = document.querySelector(".sidebar .nav-link.active") as HTMLElement;
  const tabAtual = linkAtivo ? linkAtivo.dataset.tab : "dashboard";
  if (tabAtual) carregarAba(tabAtual);
}

/* ========================================================================== */
/*                               DASHBOARD                                    */
/* ========================================================================== */

async function carregarDashboard() {
  if (!currentUser) return;
  try {
    const data = await apiFetch("/api/relatorios/dashboard");
    (document.getElementById("dQtdProdutos") as HTMLElement).textContent = String(data.qtdProdutos || 0);
    (document.getElementById("dValorEstoque") as HTMLElement).textContent = brl(data.valorEstoque || 0);
    (document.getElementById("dEstoqueBaixo") as HTMLElement).textContent = String(data.estoqueBaixo || 0);
    (document.getElementById("dQtdDevedores") as HTMLElement).textContent = String(data.qtdDevedores || 0);
    (document.getElementById("dVendidoHoje") as HTMLElement).textContent = brl(data.vendidoHoje || 0);
    (document.getElementById("dVendidoMes") as HTMLElement).textContent = brl(data.vendidoMes || 0);
    (document.getElementById("dLucroMes") as HTMLElement).textContent = brl(data.lucroMes || 0);
    (document.getElementById("dValorReceber") as HTMLElement).textContent = brl(data.valorReceber || 0);

    // Recent Sales
    const wrapUltimas = document.getElementById("dashUltimasVendas");
    if (wrapUltimas) {
      if (!data.ultimasVendas || data.ultimasVendas.length === 0) {
        wrapUltimas.innerHTML = `<div class="empty-state">Nenhuma venda registrada ainda</div>`;
      } else {
        wrapUltimas.innerHTML = data.ultimasVendas.map((v: any) => `
          <div class="d-flex justify-content-between align-items-center border-bottom py-2" style="font-size: 13px;">
            <div>
              <div class="fw-bold">${v.cliente_nome ? v.cliente_nome : 'Cliente Balcão'} <span class="badge ${v.forma_pagamento === 'Fiado' ? 'badge-pendente' : 'badge-pago'} ms-1">${v.forma_pagamento}</span></div>
              <small class="text-muted">${fmtDataHora(v.data)} — ${v.itens?.map((i: any) => `${i.nome} (x${i.qtd})`).join(', ') || 'Venda #' + v.id}</small>
            </div>
            <strong style="color:var(--accent);">${brl(v.total)}</strong>
          </div>
        `).join("");
      }
    }

    // Chart
    const ctx = (document.getElementById("chartVendasMes") as HTMLCanvasElement)?.getContext("2d");
    if (ctx && data.graficoDias) {
      if (chartVendasMesInstance) chartVendasMesInstance.destroy();
      const corTexto = getComputedStyle(document.body).getPropertyValue("--muted") || "#8a97a1";
      const corAccent = getComputedStyle(document.body).getPropertyValue("--accent") || "#2fbf8f";

      chartVendasMesInstance = new Chart(ctx, {
        type: "bar",
        data: {
          labels: data.graficoDias.dias,
          datasets: [{
            label: "Faturamento Diário (R$)",
            data: data.graficoDias.valores,
            backgroundColor: corAccent,
            borderRadius: 6,
          }],
        },
        options: {
          responsive: true,
          plugins: { legend: { display: false } },
          scales: {
            x: { ticks: { color: corTexto, font: { size: 10 } }, grid: { display: false } },
            y: { ticks: { color: corTexto, callback: (v: any) => `R$ ${v}` } },
          },
        },
      });
    }
  } catch (err: any) {
    console.error("Erro no dashboard:", err);
  }
}

/* ========================================================================== */
/*                               PRODUTOS                                     */
/* ========================================================================== */

function calcMargem() {
  const custo = parseFloat((document.getElementById("prodCusto") as HTMLInputElement).value) || 0;
  const venda = parseFloat((document.getElementById("prodVenda") as HTMLInputElement).value) || 0;
  let margem = 0;
  if (custo > 0) margem = ((venda - custo) / custo) * 100;
  (document.getElementById("prodMargem") as HTMLInputElement).value = `${margem.toFixed(1)}%`;
}

function handleFoto(ev: any) {
  const file = ev.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (e: any) => {
    const img = new Image();
    img.onload = () => {
      const maxDim = 400;
      let w = img.width, h = img.height;
      if (w > h && w > maxDim) { h = h * (maxDim / w); w = maxDim; }
      else if (h > maxDim) { w = w * (maxDim / h); h = maxDim; }
      const c = document.createElement("canvas");
      c.width = w; c.height = h;
      c.getContext("2d")?.drawImage(img, 0, 0, w, h);
      const dataUrl = c.toDataURL("image/jpeg", 0.75);
      (document.getElementById("prodFoto") as HTMLInputElement).value = dataUrl;
      setFotoPreview(dataUrl);
    };
    img.src = e.target.result;
  };
  reader.readAsDataURL(file);
}

function setFotoPreview(dataUrl: string | null) {
  const img = document.getElementById("fotoPreviewImg") as HTMLImageElement;
  const ph = document.getElementById("fotoPreviewPlaceholder") as HTMLElement;
  if (dataUrl) {
    img.src = dataUrl;
    img.style.display = "block";
    ph.style.display = "none";
  } else {
    img.style.display = "none";
    ph.style.display = "flex";
  }
}

async function carregarProdutos() {
  if (!currentUser) return;
  try {
    produtos = await apiFetch("/api/produtos");
    atualizarCategoriasSelect();
    renderProdutosFiltrados();
  } catch (err: any) {
    toast("Erro ao carregar produtos", "error");
  }
}

function atualizarCategoriasSelect() {
  const sel = document.getElementById("filtroCategoriaProduto") as HTMLSelectElement;
  if (!sel) return;
  const cats = Array.from(new Set(produtos.map((p) => p.categoria).filter(Boolean))).sort();
  const valAnterior = sel.value;
  sel.innerHTML = '<option value="">Todas as categorias</option>' + cats.map((c) => `<option value="${c}">${c}</option>`).join("");
  if (valAnterior) sel.value = valAnterior;
}

function renderProdutosFiltrados() {
  const termo = ((document.getElementById("buscaProduto") as HTMLInputElement)?.value || "").toLowerCase().trim();
  const cat = (document.getElementById("filtroCategoriaProduto") as HTMLSelectElement)?.value || "";

  const lista = produtos.filter((p) => {
    const matchTermo = !termo || `${p.nome} ${p.marca || ""} ${p.categoria || ""} ${p.codigo_interno || ""} ${p.codigo_barras || ""}`.toLowerCase().includes(termo);
    const matchCat = !cat || p.categoria === cat;
    return matchTermo && matchCat;
  });

  const tbody = document.getElementById("tbodyProdutos");
  if (!tbody) return;

  if (lista.length === 0) {
    tbody.innerHTML = `<tr><td colspan="10" class="empty-state">Nenhum produto cadastrado ou encontrado</td></tr>`;
    return;
  }

  tbody.innerHTML = lista.map((p) => {
    const margem = p.custo > 0 ? ((p.venda - p.custo) / p.custo) * 100 : 0;
    let badgeEstoque = `<span class="badge-status-ok">${p.estoque} un.</span>`;
    if (p.estoque <= 0) badgeEstoque = `<span class="badge-status-out">Esgotado (0)</span>`;
    else if (p.estoque <= p.minimo) badgeEstoque = `<span class="badge-status-low">Baixo (${p.estoque})</span>`;

    const codigoExibicao = p.codigo_barras ? `EAN: ${p.codigo_barras}` : (p.codigo_interno ? `Cód: ${p.codigo_interno}` : "-");

    return `
      <tr>
        <td>
          ${p.foto ? `<img src="${p.foto}" class="thumb-sm" alt="Foto">` : `<div class="thumb-sm d-flex align-items-center justify-content-center">📦</div>`}
        </td>
        <td>
          <div class="fw-bold">${p.nome}</div>
        </td>
        <td>${p.marca || "-"}</td>
        <td><span class="badge bg-surface2 border border-line text-muted">${p.categoria || "Geral"}</span></td>
        <td><small class="text-muted">${codigoExibicao}</small></td>
        <td class="text-end">${brl(p.custo)}</td>
        <td class="text-end fw-bold" style="color:var(--accent);">${brl(p.venda)}</td>
        <td class="text-end">${margem.toFixed(1)}%</td>
        <td class="text-end">${badgeEstoque}</td>
        <td class="text-center">
          <button class="btn btn-sm btn-outline-secondary" onclick="openProdutoModal(${p.id})" title="Editar produto">
            <i class="fa-solid fa-pen-to-square"></i>
          </button>
        </td>
      </tr>
    `;
  }).join("");
}

function openProdutoModal(id?: number) {
  (document.getElementById("produtoModalTitle") as HTMLElement).textContent = id ? "Editar Produto" : "Novo Produto";
  const btnExcluir = document.getElementById("btnExcluirProduto") as HTMLElement;
  btnExcluir.style.display = id ? "inline-block" : "none";

  if (id) {
    const p = produtos.find((x) => x.id === id);
    if (!p) return;
    (document.getElementById("prodId") as HTMLInputElement).value = String(p.id);
    (document.getElementById("prodNome") as HTMLInputElement).value = p.nome || "";
    (document.getElementById("prodMarca") as HTMLInputElement).value = p.marca || "";
    (document.getElementById("prodCategoria") as HTMLInputElement).value = p.categoria || "";
    (document.getElementById("prodCodigoInterno") as HTMLInputElement).value = p.codigo_interno || "";
    (document.getElementById("prodCodigoBarras") as HTMLInputElement).value = p.codigo_barras || "";
    (document.getElementById("prodFoto") as HTMLInputElement).value = p.foto || "";
    setFotoPreview(p.foto || null);
    (document.getElementById("prodCusto") as HTMLInputElement).value = String(p.custo);
    (document.getElementById("prodVenda") as HTMLInputElement).value = String(p.venda);
    (document.getElementById("prodEstoqueInicial") as HTMLInputElement).value = String(p.estoque);
    (document.getElementById("prodEstoqueInicial") as HTMLInputElement).disabled = true;
    (document.getElementById("prodMinimo") as HTMLInputElement).value = String(p.minimo);
  } else {
    (document.getElementById("prodId") as HTMLInputElement).value = "";
    (document.getElementById("prodFoto") as HTMLInputElement).value = "";
    setFotoPreview(null);
    ["prodNome", "prodMarca", "prodCategoria", "prodCodigoInterno", "prodCodigoBarras"].forEach((f) => {
      const el = document.getElementById(f) as HTMLInputElement;
      if (el) el.value = "";
    });
    (document.getElementById("prodCusto") as HTMLInputElement).value = "0";
    (document.getElementById("prodVenda") as HTMLInputElement).value = "0";
    (document.getElementById("prodEstoqueInicial") as HTMLInputElement).value = "10";
    (document.getElementById("prodEstoqueInicial") as HTMLInputElement).disabled = false;
    (document.getElementById("prodMinimo") as HTMLInputElement).value = "5";
  }
  calcMargem();
  bootstrap.Modal.getOrCreateInstance(document.getElementById("modalProduto")).show();
}

async function salvarProduto() {
  const nome = (document.getElementById("prodNome") as HTMLInputElement).value.trim();
  const custo = parseFloat((document.getElementById("prodCusto") as HTMLInputElement).value) || 0;
  const venda = parseFloat((document.getElementById("prodVenda") as HTMLInputElement).value) || 0;

  if (!nome || custo < 0 || venda <= 0) {
    toast("Preencha nome, custo e preço de venda válido.", "warning");
    return;
  }

  const id = (document.getElementById("prodId") as HTMLInputElement).value;
  const dados = {
    nome,
    marca: (document.getElementById("prodMarca") as HTMLInputElement).value.trim(),
    categoria: (document.getElementById("prodCategoria") as HTMLInputElement).value.trim(),
    sabor: "",
    peso: "",
    codigo_interno: (document.getElementById("prodCodigoInterno") as HTMLInputElement).value.trim(),
    codigo_barras: (document.getElementById("prodCodigoBarras") as HTMLInputElement).value.trim(),
    foto: (document.getElementById("prodFoto") as HTMLInputElement).value || "",
    custo,
    venda,
    minimo: parseFloat((document.getElementById("prodMinimo") as HTMLInputElement).value) || 5,
    estoque: parseFloat((document.getElementById("prodEstoqueInicial") as HTMLInputElement).value) || 0,
  };

  try {
    if (id) {
      await apiFetch(`/api/produtos/${id}`, { method: "PUT", body: JSON.stringify(dados) });
      toast("Produto atualizado no banco de dados");
    } else {
      await apiFetch("/api/produtos", { method: "POST", body: JSON.stringify(dados) });
      toast("Produto cadastrado com sucesso");
    }
    bootstrap.Modal.getInstance(document.getElementById("modalProduto"))?.hide();
    carregarProdutos();
  } catch (err: any) {
    toast(err.message, "error");
  }
}

/* ========================================================================== */
/*                   IMPORTAÇÃO DE PRODUTOS VIA EXCEL (.XLSX)                 */
/* ========================================================================== */

function openImportarExcelModal() {
  produtosImportacaoExcel = [];
  const fileInput = document.getElementById("inputArquivoExcel") as HTMLInputElement;
  if (fileInput) fileInput.value = "";
  
  const areaPreview = document.getElementById("areaPreviewExcel");
  if (areaPreview) areaPreview.style.display = "none";

  const btnConfirmar = document.getElementById("btnConfirmarImportacaoExcel") as HTMLButtonElement;
  if (btnConfirmar) {
    btnConfirmar.disabled = true;
    btnConfirmar.innerHTML = `<i class="fa-solid fa-cloud-arrow-up me-1"></i> Confirmar e Salvar Produtos`;
  }

  bootstrap.Modal.getOrCreateInstance(document.getElementById("modalImportarExcel")).show();
}

function normalizeExcelKey(str: any): string {
  return String(str || "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "") // remove accents
    .toLowerCase()
    .replace(/[^a-z0-9]/g, ""); // remove spaces, punctuation, symbols
}

function parseExcelValueString(val: any): string {
  if (val === undefined || val === null) return "";
  if (typeof val === "number") {
    if (Number.isInteger(val)) return val.toFixed(0);
    return String(val);
  }
  return String(val).trim();
}

function parseExcelValueNumber(val: any, def: number = 0): number {
  if (val === undefined || val === null || val === "") return def;
  if (typeof val === "number") return isNaN(val) ? def : val;
  let str = String(val).trim();
  str = str.replace(/R\$/gi, "").replace(/\$/g, "").replace(/\s/g, "");
  if (str.includes(",") && str.includes(".")) {
    str = str.replace(/\./g, "").replace(",", ".");
  } else if (str.includes(",")) {
    str = str.replace(",", ".");
  }
  const num = parseFloat(str);
  return isNaN(num) ? def : num;
}

function getFieldMapping(headerText: string): string | null {
  const k = normalizeExcelKey(headerText);
  if (!k) return null;

  // Código de Barras (EAN / GTIN / Barcode)
  if (
    k === "codigodebarras" ||
    k === "codigobarras" ||
    k === "codbarras" ||
    k === "barras" ||
    k === "ean" ||
    k === "ean13" ||
    k === "gtin" ||
    k === "upc" ||
    k === "barcode" ||
    k.includes("codigodebarra") ||
    k.includes("codbarras") ||
    k.includes("ean")
  ) {
    return "codigo_barras";
  }

  // Código Interno / SKU / Referência
  if (
    k === "codigointerno" ||
    k === "codinterno" ||
    k === "sku" ||
    k === "referencia" ||
    k === "ref" ||
    k === "codigo" ||
    k === "cod" ||
    k === "idproduto" ||
    k.includes("codigointerno") ||
    k.includes("codinterno") ||
    k.includes("sku") ||
    k.includes("referencia") ||
    (k.startsWith("cod") && !k.includes("barra"))
  ) {
    return "codigo_interno";
  }

  // Preço de Custo
  if (
    k === "custo" ||
    k === "precodecusto" ||
    k === "precocusto" ||
    k === "valordecusto" ||
    k === "valorcusto" ||
    k === "precocompra" ||
    k === "custounitario" ||
    k === "cost" ||
    k === "buyprice" ||
    k.includes("custo") ||
    k.includes("compra")
  ) {
    return "custo";
  }

  // Preço de Venda
  if (
    k === "venda" ||
    k === "precodevenda" ||
    k === "precovenda" ||
    k === "valordevenda" ||
    k === "valorvenda" ||
    k === "preco" ||
    k === "valor" ||
    k === "precounitario" ||
    k === "price" ||
    k === "sellprice" ||
    k === "pvp" ||
    k === "precoconsumidor" ||
    k.includes("precodevenda") ||
    k.includes("precovenda") ||
    k.includes("venda") ||
    k.includes("preco") ||
    k.includes("valor")
  ) {
    return "venda";
  }

  // Estoque Atual / Quantidade
  if (
    k === "estoque" ||
    k === "estoqueatual" ||
    k === "estoquefisico" ||
    k === "estoquedisponivel" ||
    k === "quantidade" ||
    k === "qtd" ||
    k === "quant" ||
    k === "qnt" ||
    k === "saldo" ||
    k === "stock" ||
    k === "quantity" ||
    k === "qty" ||
    k === "unidades" ||
    k.includes("estoqueatual") ||
    k.includes("quantidade") ||
    k.includes("estoque")
  ) {
    return "estoque";
  }

  // Estoque Mínimo
  if (
    k === "minimo" ||
    k === "estoqueminimo" ||
    k === "qtdminima" ||
    k === "quantidademinima" ||
    k === "min" ||
    k === "minstock" ||
    k.includes("minimo") ||
    k.includes("minima")
  ) {
    return "minimo";
  }

  // Marca / Fabricante
  if (
    k === "marca" ||
    k === "marcadoproduto" ||
    k === "brand" ||
    k === "fabricante" ||
    k === "laboratorio" ||
    k === "fornecedor" ||
    k.includes("marca") ||
    k.includes("fabricante")
  ) {
    return "marca";
  }

  // Categoria / Grupo / Departamento
  if (
    k === "categoria" ||
    k === "categoriadoproduto" ||
    k === "category" ||
    k === "grupo" ||
    k === "departamento" ||
    k === "secao" ||
    k === "linha" ||
    k === "tipo" ||
    k === "classe" ||
    k === "familia" ||
    k.includes("categoria") ||
    k.includes("departamento")
  ) {
    return "categoria";
  }

  // Nome do produto / Descrição / Item
  if (
    k === "nome" ||
    k === "nomedoproduto" ||
    k === "nomeproduto" ||
    k === "produto" ||
    k === "produtos" ||
    k === "descricao" ||
    k === "descricaodoproduto" ||
    k === "descricaoproduto" ||
    k === "desc" ||
    k === "item" ||
    k === "itens" ||
    k === "titulo" ||
    k === "artigo" ||
    k === "mercadoria" ||
    k === "product" ||
    k === "productname" ||
    k === "description" ||
    k === "especificacao" ||
    k === "especificacaodoproduto" ||
    k === "detalhe" ||
    k === "designacao" ||
    k.includes("nomedoprod") ||
    k.includes("descricaodoprod") ||
    k.includes("nome") ||
    k.includes("prod") ||
    k.includes("desc")
  ) {
    return "nome";
  }

  return null;
}

function handleExcelFileUpload(event: Event) {
  const target = event.target as HTMLInputElement;
  const file = target.files?.[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = (e: any) => {
    try {
      const data = new Uint8Array(e.target.result);
      const workbook = XLSX.read(data, { type: "array" });

      const firstSheetName = workbook.SheetNames[0];
      if (!firstSheetName) {
        toast("Nenhuma planilha encontrada no arquivo.", "error");
        return;
      }

      const worksheet = workbook.Sheets[firstSheetName];
      const sheetData: any[][] = XLSX.utils.sheet_to_json(worksheet, { header: 1, defval: "" });

      if (!sheetData || sheetData.length === 0) {
        toast("A planilha selecionada está vazia.", "warning");
        return;
      }

      processarMatrizPlanilha(sheetData);
    } catch (err: any) {
      console.error("Erro ao ler arquivo Excel:", err);
      toast("Erro ao ler arquivo Excel. Verifique se o formato é válido (.xlsx, .xls ou .csv)", "error");
    }
  };
  reader.readAsArrayBuffer(file);
}

function processarMatrizPlanilha(sheetData: any[][]) {
  produtosImportacaoExcel = [];

  // 1. Localizar a linha de cabeçalho (analisando as primeiras 15 linhas)
  let bestHeaderRowIndex = -1;
  let maxMatchedFields = 0;
  let bestColMapping: { [colIndex: number]: string } = {};

  const scanLimit = Math.min(15, sheetData.length);
  for (let r = 0; r < scanLimit; r++) {
    const row = sheetData[r];
    if (!Array.isArray(row)) continue;

    const currentMapping: { [colIndex: number]: string } = {};
    let matchedCount = 0;

    row.forEach((cellVal, colIdx) => {
      const field = getFieldMapping(String(cellVal));
      if (field && !Object.values(currentMapping).includes(field)) {
        currentMapping[colIdx] = field;
        matchedCount++;
      }
    });

    if (matchedCount > maxMatchedFields) {
      maxMatchedFields = matchedCount;
      bestHeaderRowIndex = r;
      bestColMapping = currentMapping;
    }
  }

  // Se nenhuma linha de cabeçalho foi detectada com certeza, assumir a primeira linha (linha 0)
  if (bestHeaderRowIndex === -1 || maxMatchedFields === 0) {
    bestHeaderRowIndex = 0;
    const row0 = sheetData[0] || [];
    row0.forEach((cellVal, colIdx) => {
      const field = getFieldMapping(String(cellVal));
      if (field) bestColMapping[colIdx] = field;
    });
  }

  // Se ainda não mapeou "nome", usar a primeira coluna com texto como "nome"
  if (!Object.values(bestColMapping).includes("nome")) {
    const headerRow = sheetData[bestHeaderRowIndex] || [];
    for (let c = 0; c < headerRow.length; c++) {
      if (!bestColMapping[c]) {
        bestColMapping[c] = "nome";
        break;
      }
    }
  }

  // 2. Processar cada linha de dados a partir de headerRowIndex + 1
  for (let r = bestHeaderRowIndex + 1; r < sheetData.length; r++) {
    const row = sheetData[r];
    if (!Array.isArray(row) || row.length === 0) continue;

    // Verificar se a linha não está completamente vazia
    const temConteudo = row.some((c) => c !== undefined && c !== null && String(c).trim() !== "");
    if (!temConteudo) continue;

    const rowObj: any = {
      nome: "",
      marca: "",
      categoria: "",
      codigo_interno: "",
      codigo_barras: "",
      custo: 0,
      venda: 0,
      estoque: 0,
      minimo: 5,
    };

    // Preencher campos de acordo com o mapeamento de colunas
    row.forEach((cellVal, colIdx) => {
      const field = bestColMapping[colIdx];
      if (!field) return;

      if (field === "custo" || field === "venda" || field === "estoque" || field === "minimo") {
        rowObj[field] = parseExcelValueNumber(cellVal, field === "minimo" ? 5 : 0);
      } else {
        rowObj[field] = parseExcelValueString(cellVal);
      }
    });

    // Se o nome ficou vazio, tentar pegar o primeiro texto não numérico da linha
    if (!rowObj.nome) {
      for (const cell of row) {
        const str = parseExcelValueString(cell);
        if (str && str.length > 1 && isNaN(Number(str.replace(",", ".")))) {
          rowObj.nome = str;
          break;
        }
      }
    }

    // Se ainda não tiver nome após todas as tentativas, pula a linha
    if (!rowObj.nome) continue;

    // Identificar se o produto já existe no catálogo do sistema
    const existente = produtos.find(
      (p) =>
        (rowObj.codigo_barras && p.codigo_barras && p.codigo_barras === rowObj.codigo_barras) ||
        (rowObj.codigo_interno && p.codigo_interno && p.codigo_interno === rowObj.codigo_interno) ||
        p.nome.trim().toLowerCase() === rowObj.nome.toLowerCase()
    );

    produtosImportacaoExcel.push({
      nome: rowObj.nome,
      marca: rowObj.marca,
      categoria: rowObj.categoria,
      codigo_interno: rowObj.codigo_interno,
      codigo_barras: rowObj.codigo_barras,
      custo: rowObj.custo,
      venda: rowObj.venda,
      estoque: rowObj.estoque,
      minimo: rowObj.minimo,
      status: existente ? "Atualização" : "Novo",
      existenteId: existente?.id,
    });
  }

  if (produtosImportacaoExcel.length === 0) {
    toast(
      "Nenhum produto válido encontrado. Certifique-se de que a planilha possui colunas como 'Nome do Produto', 'Preço de Venda' e 'Estoque'.",
      "warning"
    );
    return;
  }

  toast(`${produtosImportacaoExcel.length} produto(s) lido(s) com sucesso da planilha!`, "success");
  renderPreviewExcel();
}

function renderPreviewExcel() {
  const tbody = document.getElementById("tbodyPreviewExcel");
  const areaPreview = document.getElementById("areaPreviewExcel");
  const badgeTotal = document.getElementById("badgeTotalLidosExcel");
  const btnConfirmar = document.getElementById("btnConfirmarImportacaoExcel") as HTMLButtonElement;

  if (!tbody || !areaPreview) return;

  const total = produtosImportacaoExcel.length;
  const novos = produtosImportacaoExcel.filter((p) => p.status === "Novo").length;
  const atualizacoes = total - novos;

  if (badgeTotal) {
    badgeTotal.textContent = `${total} itens encontrados (${novos} novos, ${atualizacoes} existentes)`;
  }

  tbody.innerHTML = produtosImportacaoExcel
    .slice(0, 100) // Limite de 100 na prévia visual para altíssima fluidez
    .map((p) => {
      const isNovo = p.status === "Novo";
      const statusBadge = isNovo
        ? `<span class="badge bg-success-subtle text-success border border-success" style="font-size:11px;">+ Novo</span>`
        : `<span class="badge bg-warning-subtle text-warning border border-warning" style="font-size:11px;">⟳ Atualizar</span>`;

      return `
        <tr>
          <td>${statusBadge}</td>
          <td class="fw-bold">${p.nome}</td>
          <td>${p.marca || "-"}</td>
          <td><span class="badge bg-surface2 text-muted border">${p.categoria || "Geral"}</span></td>
          <td><small class="text-muted">${p.codigo_interno || "-"}</small></td>
          <td><small class="text-muted">${p.codigo_barras || "-"}</small></td>
          <td class="text-end">${brl(p.custo)}</td>
          <td class="text-end fw-bold" style="color:var(--accent);">${brl(p.venda)}</td>
          <td class="text-end">${p.estoque} un.</td>
          <td class="text-end">${p.minimo}</td>
        </tr>
      `;
    })
    .join("");

  if (total > 100) {
    tbody.innerHTML += `
      <tr>
        <td colspan="10" class="text-center py-2 bg-surface2 text-muted fst-italic">
          ... e mais ${total - 100} produtos adicionais prontos para importação.
        </td>
      </tr>
    `;
  }

  areaPreview.style.display = "block";
  if (btnConfirmar) {
    btnConfirmar.disabled = false;
    btnConfirmar.innerHTML = `<i class="fa-solid fa-cloud-arrow-up me-1"></i> Confirmar Importação de ${total} Produtos`;
  }
}

function baixarModeloPlanilhaExcel() {
  const dadosModelo = [
    {
      "Nome do Produto": "Creatina Monohidratada 300g",
      "Marca": "Max Titanium",
      "Categoria": "Aminoácidos",
      "Código Interno": "CR-001",
      "Código de Barras": "7891000100011",
      "Preço de Custo": 45.0,
      "Preço de Venda": 89.9,
      "Estoque Atual": 20,
      "Estoque Mínimo": 5,
    },
    {
      "Nome do Produto": "Whey Protein Concentrado 900g",
      "Marca": "IntegralMedica",
      "Categoria": "Proteínas",
      "Código Interno": "WP-002",
      "Código de Barras": "7891000100028",
      "Preço de Custo": 65.0,
      "Preço de Venda": 129.9,
      "Estoque Atual": 15,
      "Estoque Mínimo": 4,
    },
    {
      "Nome do Produto": "Barra de Proteína Crisp 45g",
      "Marca": "IntegralMedica",
      "Categoria": "Snacks",
      "Código Interno": "BAR-003",
      "Código de Barras": "7891000100035",
      "Preço de Custo": 3.5,
      "Preço de Venda": 7.5,
      "Estoque Atual": 50,
      "Estoque Mínimo": 10,
    },
    {
      "Nome do Produto": "BCAA 2:1:1 120 Cápsulas",
      "Marca": "Growth",
      "Categoria": "Aminoácidos",
      "Código Interno": "BCAA-004",
      "Código de Barras": "7891000100042",
      "Preço de Custo": 28.0,
      "Preço de Venda": 54.9,
      "Estoque Atual": 12,
      "Estoque Mínimo": 3,
    },
    {
      "Nome do Produto": "Coqueteleira Shaker 600ml",
      "Marca": "Probiótica",
      "Categoria": "Acessórios",
      "Código Interno": "AC-005",
      "Código de Barras": "7891000100059",
      "Preço de Custo": 9.0,
      "Preço de Venda": 22.0,
      "Estoque Atual": 25,
      "Estoque Mínimo": 5,
    },
  ];

  const ws = XLSX.utils.json_to_sheet(dadosModelo);
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, ws, "Produtos");
  XLSX.writeFile(wb, "modelo_importacao_produtos.xlsx");
  toast("Planilha modelo baixada com sucesso!", "success");
}

async function processarImportacaoExcel() {
  if (produtosImportacaoExcel.length === 0) {
    toast("Nenhum produto para importar.", "warning");
    return;
  }

  const chkAtualizar = document.getElementById("chkAtualizarExistentes") as HTMLInputElement;
  const atualizarExistentes = chkAtualizar ? chkAtualizar.checked : true;

  const btnConfirmar = document.getElementById("btnConfirmarImportacaoExcel") as HTMLButtonElement;
  btnConfirmar.disabled = true;
  btnConfirmar.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span> Salvando produtos no banco...`;

  try {
    const res = await apiFetch("/api/produtos/importar-lote", {
      method: "POST",
      body: JSON.stringify({
        itens: produtosImportacaoExcel,
        atualizarExistentes,
      }),
    });

    Swal.fire({
      title: "Importação Concluída!",
      text: res.message || `${res.inseridos} produtos inseridos e ${res.atualizados} atualizados.`,
      icon: "success",
      confirmButtonText: "Entendido",
      confirmButtonColor: "var(--accent)",
    });

    bootstrap.Modal.getInstance(document.getElementById("modalImportarExcel"))?.hide();
    carregarProdutos();
    carregarEstoque();
  } catch (err: any) {
    console.error("Erro na importação:", err);
    Swal.fire({
      title: "Erro na importação",
      text: err.message || "Não foi possível importar a planilha.",
      icon: "error",
    });
  } finally {
    btnConfirmar.disabled = false;
    btnConfirmar.innerHTML = `<i class="fa-solid fa-cloud-arrow-up me-1"></i> Confirmar e Salvar Produtos`;
  }
}

async function excluirProduto() {
  const id = (document.getElementById("prodId") as HTMLInputElement).value;
  if (!id) return;

  Swal.fire({
    title: "Excluir produto?",
    text: "O produto será desvinculado do catálogo. O histórico de vendas passadas será mantido.",
    icon: "warning",
    showCancelButton: true,
    confirmButtonText: "Sim, excluir",
    confirmButtonColor: "#e05a4e",
    cancelButtonText: "Cancelar",
  }).then(async (r: any) => {
    if (r.isConfirmed) {
      try {
        await apiFetch(`/api/produtos/${id}`, { method: "DELETE" });
        bootstrap.Modal.getInstance(document.getElementById("modalProduto"))?.hide();
        toast("Produto removido com sucesso");
        carregarProdutos();
      } catch (err: any) {
        toast(err.message, "error");
      }
    }
  });
}

/* ========================================================================== */
/*                               ESTOQUE                                      */
/* ========================================================================== */

function setupEstoqueTabs() {
  document.querySelectorAll("#estoqueTabs .nav-link").forEach((l) => {
    l.addEventListener("click", (e) => {
      e.preventDefault();
      document.querySelectorAll("#estoqueTabs .nav-link").forEach((x) => x.classList.remove("active"));
      l.classList.add("active");
      const est = (l as HTMLElement).dataset.est;
      ["visao", "mov", "hist"].forEach((k) => {
        const el = document.getElementById(`est-${k}`);
        if (el) el.style.display = k === est ? "block" : "none";
      });
      if (est === "mov") popularSelectProdutosEstoque();
      if (est === "hist") carregarHistoricoEstoque();
    });
  });
}

function toggleMovCampos() {
  const tipo = (document.getElementById("movTipo") as HTMLSelectElement).value;
  const wrapCusto = document.getElementById("movCustoWrap");
  const labelQtd = document.getElementById("movQtdLabel");
  if (wrapCusto) wrapCusto.style.display = tipo === "entrada" ? "block" : "none";
  if (labelQtd) labelQtd.textContent = tipo === "ajuste" ? "Novo saldo em estoque" : "Quantidade";
}

function popularSelectProdutosEstoque() {
  const sel = document.getElementById("movProduto") as HTMLSelectElement;
  if (!sel) return;
  sel.innerHTML = produtos.map((p) => `<option value="${p.id}">${p.nome} (Atual: ${p.estoque})</option>`).join("");
}

function renderEstoqueVisao() {
  const valorTotal = produtos.reduce((s, p) => s + p.estoque * p.custo, 0);
  const elTotal = document.getElementById("estValorTotal");
  if (elTotal) elTotal.textContent = brl(valorTotal);

  const tbody = document.getElementById("tbodyEstoqueVisao");
  if (tbody) {
    if (produtos.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" class="empty-state">Nenhum produto cadastrado no estoque</td></tr>`;
      return;
    }
    tbody.innerHTML = produtos
      .map((p) => {
        let badge = `<span class="badge-status-ok">Normal</span>`;
        if (p.estoque <= 0) badge = `<span class="badge-status-out">Esgotado</span>`;
        else if (p.estoque <= p.minimo) badge = `<span class="badge-status-low">Baixo</span>`;

        return `
        <tr>
          <td><strong>${p.nome}</strong></td>
          <td class="text-end fw-bold">${p.estoque}</td>
          <td class="text-end text-muted">${p.minimo}</td>
          <td class="text-end">${brl(p.custo)}</td>
          <td class="text-end fw-bold">${brl(p.estoque * p.custo)}</td>
          <td>${badge}</td>
        </tr>
      `;
      })
      .join("");
  }
}

async function carregarEstoque() {
  if (produtos.length === 0) {
    await carregarProdutos();
  }
  renderEstoqueVisao();
}

function renderHistoricoEstoqueFromList(list: any[]) {
  const tbody = document.getElementById("tbodyHistoricoEstoque");
  if (!tbody) return;

  if (!list || list.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" class="empty-state">Nenhuma movimentação registrada</td></tr>`;
    return;
  }

  const labels: Record<string, string> = { entrada: "Entrada", saida: "Saída", ajuste: "Ajuste" };
  const badges: Record<string, string> = { entrada: "bg-success", saida: "bg-danger", ajuste: "bg-warning" };

  tbody.innerHTML = list
    .map((m: any) => `
      <tr>
        <td>${fmtDataHora(m.data)}</td>
        <td><strong>${m.produto_nome || "Produto #" + m.produto_id}</strong></td>
        <td><span class="badge ${badges[m.tipo] || "bg-secondary"}">${labels[m.tipo] || m.tipo}</span></td>
        <td class="text-end">${m.tipo === "ajuste" ? `${m.qtd_anterior} → ${m.qtd_nova}` : m.qtd}</td>
        <td>${m.motivo || "-"}</td>
      </tr>
    `)
    .join("");
}

async function carregarHistoricoEstoque() {
  try {
    const hist = await apiFetch("/api/estoque/movimentacoes");
    movimentacoes = hist;
    renderHistoricoEstoqueFromList(hist);
  } catch (err: any) {
    if (movimentacoes.length > 0) {
      renderHistoricoEstoqueFromList(movimentacoes);
    } else {
      toast("Erro ao carregar histórico de estoque", "error");
    }
  }
}

async function salvarMovimentacao() {
  const produto_id = (document.getElementById("movProduto") as HTMLSelectElement).value;
  const tipo = (document.getElementById("movTipo") as HTMLSelectElement).value;
  const qtd = parseFloat((document.getElementById("movQtd") as HTMLInputElement).value);
  const custo_unit = parseFloat((document.getElementById("movCusto") as HTMLInputElement).value) || 0;
  const motivo = (document.getElementById("movMotivo") as HTMLInputElement).value.trim();

  if (!produto_id || isNaN(qtd) || qtd <= 0) {
    toast("Informe produto e quantidade válida", "warning");
    return;
  }

  try {
    await apiFetch("/api/estoque/movimentar", {
      method: "POST",
      body: JSON.stringify({ produto_id, tipo, qtd, custo_unit, motivo }),
    });

    (document.getElementById("movQtd") as HTMLInputElement).value = "";
    (document.getElementById("movMotivo") as HTMLInputElement).value = "";
    toast("Movimentação registrada com sucesso");
    carregarEstoque();
  } catch (err: any) {
    toast(err.message, "error");
  }
}

/* ========================================================================== */
/*                               VENDAS (PDV)                                 */
/* ========================================================================== */

function buscarProdutoVenda() {
  const termo = ((document.getElementById("vendaBusca") as HTMLInputElement)?.value || "").toLowerCase().trim();
  const box = document.getElementById("vendaSugestoes");
  if (!box) return;

  if (!termo) {
    box.style.display = "none";
    return;
  }

  const resultados = produtos.filter((p) => `${p.nome} ${p.codigo_barras || ""} ${p.marca || ""}`.toLowerCase().includes(termo)).slice(0, 8);

  if (resultados.length === 0) {
    box.innerHTML = `<div class="item text-muted">Nenhum produto encontrado</div>`;
  } else {
    box.innerHTML = resultados.map((p) => `
      <div class="item" onclick="adicionarAoCarrinho(${p.id})">
        <strong>${p.nome}</strong> ${p.marca ? `- ${p.marca}` : ""}
        <span class="text-muted ms-1">(${p.estoque} em estoque · <strong>${brl(p.venda)}</strong>)</span>
      </div>
    `).join("");
  }
  box.style.display = "block";
}

function adicionarAoCarrinho(produtoId: number) {
  const p = produtos.find((x) => x.id === produtoId);
  if (!p) return;
  if (p.estoque <= 0) {
    toast(`Produto "${p.nome}" sem estoque disponível`, "error");
    return;
  }

  const itemExistente = carrinho.find((i) => i.produtoId === produtoId);
  if (itemExistente) {
    if (itemExistente.qtd < p.estoque) {
      itemExistente.qtd++;
    } else {
      toast(`Estoque máximo atingido (${p.estoque} unidades)`, "warning");
    }
  } else {
    carrinho.push({
      produtoId: p.id,
      nome: p.nome,
      qtd: 1,
      precoUnit: p.venda,
      custoUnit: p.custo,
      estoqueMax: p.estoque,
    });
  }

  (document.getElementById("vendaBusca") as HTMLInputElement).value = "";
  const box = document.getElementById("vendaSugestoes");
  if (box) box.style.display = "none";

  atualizarCarrinho();
}

function alterarQtdCarrinho(produtoId: number, qtdRaw: string) {
  const item = carrinho.find((i) => i.produtoId === produtoId);
  if (!item) return;
  let qtd = parseInt(qtdRaw) || 1;
  qtd = Math.max(1, qtd);
  if (qtd > item.estoqueMax) {
    toast(`Só há ${item.estoqueMax} unidades em estoque`, "warning");
    qtd = item.estoqueMax;
  }
  item.qtd = qtd;
  atualizarCarrinho();
}

function removerDoCarrinho(produtoId: number) {
  carrinho = carrinho.filter((i) => i.produtoId !== produtoId);
  atualizarCarrinho();
}

function limparCarrinho() {
  carrinho = [];
  atualizarCarrinho();
}

function atualizarCarrinho() {
  const wrap = document.getElementById("carrinhoItens");
  if (!wrap) return;

  if (carrinho.length === 0) {
    wrap.innerHTML = `<div class="empty-state">Nenhum item no carrinho</div>`;
  } else {
    wrap.innerHTML = carrinho.map((i) => `
      <div class="cart-item">
        <div class="flex-grow-1">
          <div class="fw-bold" style="font-size:13.5px;">${i.nome}</div>
          <small class="text-muted">${brl(i.precoUnit)} cada (Disp: ${i.estoqueMax})</small>
        </div>
        <input type="number" class="form-control qty-input text-center" min="1" max="${i.estoqueMax}" value="${i.qtd}" onchange="alterarQtdCarrinho(${i.produtoId}, this.value)">
        <strong style="min-width:75px; text-align:right; color:var(--accent);">${brl(i.qtd * i.precoUnit)}</strong>
        <button class="btn btn-sm btn-outline-danger" onclick="removerDoCarrinho(${i.produtoId})" title="Remover"><i class="fa-solid fa-trash"></i></button>
      </div>
    `).join("");
  }

  const subtotal = carrinho.reduce((sum, i) => sum + (i.qtd * i.precoUnit), 0);
  const tipoDesc = (document.getElementById("vDescontoTipo") as HTMLSelectElement)?.value || "valor";
  const valDescInput = parseFloat((document.getElementById("vDescontoValor") as HTMLInputElement)?.value) || 0;
  const descontoCalculado = tipoDesc === "percentual" ? subtotal * (valDescInput / 100) : valDescInput;
  const total = Math.max(0, subtotal - descontoCalculado);

  (document.getElementById("vSubtotal") as HTMLElement).textContent = brl(subtotal);
  (document.getElementById("vTotal") as HTMLElement).textContent = brl(total);
}

function toggleFiadoCampos() {
  const forma = (document.getElementById("vFormaPagamento") as HTMLSelectElement).value;
  const wrap = document.getElementById("vFiadoCampos");
  if (wrap) wrap.style.display = forma === "Fiado" ? "block" : "none";
  if (forma === "Fiado") {
    popularSelectClientesVenda();
  }
}

function popularSelectClientesVenda() {
  const sel = document.getElementById("vCliente") as HTMLSelectElement;
  if (!sel) return;
  sel.innerHTML = clientes.map((c) => `<option value="${c.id}">${c.nome} (${c.telefone || "Sem fone"})</option>`).join("") || `<option disabled>Cadastre um cliente primeiro</option>`;
}

function popularSelectVendedoresVenda() {
  const sel = document.getElementById("vVendedor") as HTMLSelectElement;
  const filtroSel = document.getElementById("vendasFiltroVendedor") as HTMLSelectElement;

  const ativos = vendedores.filter((v) => v.ativo !== 0);
  const options = ativos.map((v) => `<option value="${v.id}">${v.nome}</option>`).join("");

  if (sel) {
    sel.innerHTML = `<option value="">Selecione o vendedor...</option>` + options;
    if (currentUser?.role === "vendedor" || currentUser?.role === "caixa") {
      const match = ativos.find((v) => v.user_id === currentUser?.id || v.nome.toLowerCase().includes(currentUser?.nome.toLowerCase().split(" ")[0]));
      if (match) {
        sel.value = String(match.id);
      }
    }
  }
  if (filtroSel) {
    filtroSel.innerHTML = `<option value="todos">Todos os vendedores</option>` + options;
  }
}

async function finalizarVenda() {
  if (carrinho.length === 0) {
    toast("O carrinho está vazio", "warning");
    return;
  }

  const vendedorId = (document.getElementById("vVendedor") as HTMLSelectElement).value;
  if (!vendedorId) {
    toast("Selecione o vendedor responsável pela venda", "warning");
    return;
  }

  const formaPagamento = (document.getElementById("vFormaPagamento") as HTMLSelectElement).value;
  let clienteId: string | null = null;
  let dataPrevista: string | null = null;

  if (formaPagamento === "Fiado") {
    clienteId = (document.getElementById("vCliente") as HTMLSelectElement).value;
    dataPrevista = (document.getElementById("vDataPrevista") as HTMLInputElement).value;
    if (!clienteId) {
      toast("Selecione o cliente para venda fiado", "warning");
      return;
    }
  }

  const subtotal = carrinho.reduce((sum, i) => sum + (i.qtd * i.precoUnit), 0);
  const tipoDesc = (document.getElementById("vDescontoTipo") as HTMLSelectElement).value;
  const valDescInput = parseFloat((document.getElementById("vDescontoValor") as HTMLInputElement).value) || 0;
  const desconto = tipoDesc === "percentual" ? subtotal * (valDescInput / 100) : valDescInput;

  const payload = {
    itens: carrinho,
    clienteId,
    vendedorId,
    desconto,
    formaPagamento,
    dataPrevista,
  };

  const btn = document.getElementById("btnFinalizarVenda") as HTMLButtonElement;
  btn.disabled = true;
  btn.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span> Gravando venda no banco...`;

  try {
    const res = await apiFetch("/api/vendas", {
      method: "POST",
      body: JSON.stringify(payload),
    });

    toast(`Venda #${res.vendaId} registrada com sucesso!`, "success");
    limparCarrinho();
    (document.getElementById("vDescontoValor") as HTMLInputElement).value = "0";
    (document.getElementById("vFormaPagamento") as HTMLSelectElement).value = "Dinheiro";
    toggleFiadoCampos();

    // Reload sales and products stock
    carregarProdutos();
    carregarVendasFiltradas();
  } catch (err: any) {
    toast(err.message, "error");
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<i class="fa-solid fa-circle-check me-2"></i> Confirmar e Gravar Venda`;
  }
}

/* ========================================================================== */
/*                FILTRO DE VENDAS POR PERÍODO                                */
/* ========================================================================== */

function setPresetFiltroVendas(preset: string, autoFetch: boolean = true) {
  const hoje = new Date();
  const hojeStr = hoje.toISOString().slice(0, 10);
  const deInput = document.getElementById("vendasFiltroDe") as HTMLInputElement;
  const ateInput = document.getElementById("vendasFiltroAte") as HTMLInputElement;

  if (preset === "hoje") {
    deInput.value = hojeStr;
    ateInput.value = hojeStr;
  } else if (preset === "7dias") {
    const d7 = new Date(Date.now() - 7 * 86400000).toISOString().slice(0, 10);
    deInput.value = d7;
    ateInput.value = hojeStr;
  } else if (preset === "mesAtual") {
    const dInicio = new Date(hoje.getFullYear(), hoje.getMonth(), 1).toISOString().slice(0, 10);
    deInput.value = dInicio;
    ateInput.value = hojeStr;
  } else if (preset === "mesAnterior") {
    const dInicioAnt = new Date(hoje.getFullYear(), hoje.getMonth() - 1, 1).toISOString().slice(0, 10);
    const dFimAnt = new Date(hoje.getFullYear(), hoje.getMonth(), 0).toISOString().slice(0, 10);
    deInput.value = dInicioAnt;
    ateInput.value = dFimAnt;
  } else if (preset === "anoAtual") {
    const dInicioAno = `${hoje.getFullYear()}-01-01`;
    deInput.value = dInicioAno;
    ateInput.value = hojeStr;
  }

  if (autoFetch && currentUser) {
    carregarVendasFiltradas();
  }
}

function limparFiltroVendas() {
  (document.getElementById("vendasFiltroDe") as HTMLInputElement).value = "";
  (document.getElementById("vendasFiltroAte") as HTMLInputElement).value = "";
  (document.getElementById("vendasFiltroForma") as HTMLSelectElement).value = "todas";
  (document.getElementById("vendasFiltroVendedor") as HTMLSelectElement).value = "todos";
  if (currentUser) {
    carregarVendasFiltradas();
  }
}

async function carregarVendasFiltradas() {
  if (!currentUser) return;

  const de = (document.getElementById("vendasFiltroDe") as HTMLInputElement)?.value;
  const ate = (document.getElementById("vendasFiltroAte") as HTMLInputElement)?.value;
  const formaPagamento = (document.getElementById("vendasFiltroForma") as HTMLSelectElement)?.value;
  const vendedorId = (document.getElementById("vendasFiltroVendedor") as HTMLSelectElement)?.value;

  const params = new URLSearchParams();
  if (de) params.set("de", de);
  if (ate) params.set("ate", ate);
  if (formaPagamento && formaPagamento !== "todas") params.set("formaPagamento", formaPagamento);
  if (vendedorId && vendedorId !== "todos") params.set("vendedorId", vendedorId);

  try {
    const data = await apiFetch(`/api/vendas?${params.toString()}`);
    const vendas = data.vendas || [];
    const metricas = data.metricas || {};

    // Update period summary cards
    (document.getElementById("resFaturamentoPeriodo") as HTMLElement).textContent = brl(metricas.totalFaturamento || 0);
    (document.getElementById("resLucroPeriodo") as HTMLElement).textContent = brl(metricas.totalLucro || 0);
    (document.getElementById("resQtdVendasPeriodo") as HTMLElement).textContent = String(metricas.qtdVendas || 0);
    (document.getElementById("resTicketMedioPeriodo") as HTMLElement).textContent = brl(metricas.ticketMedio || 0);

    const tbody = document.getElementById("tbodyVendas");
    if (!tbody) return;

    if (vendas.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="empty-state">Nenhuma venda encontrada para o período selecionado</td></tr>`;
      return;
    }

    tbody.innerHTML = vendas.map((v: any) => `
      <tr>
        <td><strong>#${v.id}</strong></td>
        <td>${fmtDataHora(v.data)}</td>
        <td>
          <div>${v.itens?.map((i: any) => `${i.nome} (x${i.qtd})`).join(", ") || "-"}</div>
          <small class="text-muted">${v.cliente_nome ? `Cliente: ${v.cliente_nome}` : "Consumidor Final"}</small>
        </td>
        <td>${v.vendedor_nome || "-"}</td>
        <td class="text-end fw-bold" style="color:var(--accent);">${brl(v.total)}</td>
        <td><span class="badge ${v.forma_pagamento === 'Fiado' ? 'badge-pendente' : 'badge-pago'}">${v.forma_pagamento}</span></td>
        <td class="text-center">
          <button class="btn btn-sm btn-outline-secondary" onclick="verReciboVenda(${v.id})" title="Ver recibo">
            <i class="fa-solid fa-receipt"></i>
          </button>
        </td>
      </tr>
    `).join("");
  } catch (err: any) {
    console.error("Erro ao filtrar vendas:", err);
  }
}

let vendaAtualId: number | null = null;
async function verReciboVenda(id: number) {
  try {
    const data = await apiFetch(`/api/vendas?id=${id}`);
    const v = data.vendas?.find((x: any) => x.id === id);
    if (!v) return;

    vendaAtualId = id;
    (document.getElementById("reciboTitulo") as HTMLElement).textContent = `Recibo da Venda #${v.id}`;
    const btnCanc = document.getElementById("btnCancelarVendaModal") as HTMLElement;
    btnCanc.style.display = currentUser?.role === "admin" ? "inline-block" : "none";

    const wrap = document.getElementById("reciboConteudo");
    if (wrap) {
      wrap.innerHTML = `
        <div class="text-center pb-3 border-bottom mb-3">
          <h5 class="fw-bold mb-1">${(document.getElementById("topbarNome") as HTMLElement).textContent}</h5>
          <small class="text-muted">Data/Hora: ${fmtDataHora(v.data)}</small>
        </div>
        <div class="mb-3" style="font-size:13px;">
          <div><strong>Vendedor:</strong> ${v.vendedor_nome || "Balcão"}</div>
          <div><strong>Cliente:</strong> ${v.cliente_nome || "Consumidor Final"}</div>
          <div><strong>Forma de Pagamento:</strong> ${v.forma_pagamento}</div>
        </div>
        <table class="table table-sm mb-3" style="font-size:13px;">
          <thead><tr><th>Item</th><th class="text-center">Qtd</th><th class="text-end">Unit.</th><th class="text-end">Total</th></tr></thead>
          <tbody>
            ${v.itens?.map((i: any) => `
              <tr>
                <td>${i.nome}</td>
                <td class="text-center">${i.qtd}</td>
                <td class="text-end">${brl(i.preco_unit)}</td>
                <td class="text-end">${brl(i.qtd * i.preco_unit)}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
        <div class="d-flex justify-content-between mb-1"><span class="text-muted">Subtotal:</span><span>${brl(v.subtotal)}</span></div>
        <div class="d-flex justify-content-between mb-1"><span class="text-muted">Desconto:</span><span class="text-danger">-${brl(v.desconto)}</span></div>
        <div class="d-flex justify-content-between fs-5 fw-bold border-top pt-2"><span>Total:</span><span style="color:var(--accent);">${brl(v.total)}</span></div>
      `;
    }
    bootstrap.Modal.getOrCreateInstance(document.getElementById("modalReciboVenda")).show();
  } catch (e) {}
}

function imprimirRecibo() {
  const content = document.getElementById("reciboConteudo")?.innerHTML;
  if (!content) return;
  (document.getElementById("printArea") as HTMLElement).innerHTML = `
    <div style="max-width:320px;margin:0 auto;font-family:monospace;">
      ${content}
    </div>
  `;
  window.print();
}

async function cancelarVendaAtual() {
  if (!vendaAtualId) return;
  Swal.fire({
    title: `Cancelar Venda #${vendaAtualId}?`,
    text: "A venda será estornada e todo o estoque dos produtos será devolvido automaticamente.",
    icon: "warning",
    showCancelButton: true,
    confirmButtonText: "Sim, estornar venda",
    confirmButtonColor: "#e05a4e",
    cancelButtonText: "Voltar",
  }).then(async (r: any) => {
    if (r.isConfirmed) {
      try {
        await apiFetch(`/api/vendas/${vendaAtualId}`, { method: "DELETE" });
        bootstrap.Modal.getInstance(document.getElementById("modalReciboVenda"))?.hide();
        toast("Venda cancelada e estoque restaurado");
        carregarProdutos();
        carregarVendasFiltradas();
      } catch (err: any) {
        toast(err.message, "error");
      }
    }
  });
}

/* ========================================================================== */
/*                RELATÓRIO DE DESEMPENHO MENSAL DETALHADO                    */
/* ========================================================================== */

function setupRelatoriosTabs() {
  document.querySelectorAll("#relTabs .nav-link").forEach((l) => {
    l.addEventListener("click", (e) => {
      e.preventDefault();
      document.querySelectorAll("#relTabs .nav-link").forEach((x) => x.classList.remove("active"));
      l.classList.add("active");
      relatorioAtivo = (l as HTMLElement).dataset.rel || "mensal";

      const wrapMensal = document.getElementById("rel-conteudo-mensal");
      const wrapGenerico = document.getElementById("relatorioConteudoGenerico");

      if (relatorioAtivo === "mensal") {
        if (wrapMensal) wrapMensal.style.display = "block";
        if (wrapGenerico) wrapGenerico.style.display = "none";
        carregarRelatorioMensalDetalhado();
      } else {
        if (wrapMensal) wrapMensal.style.display = "none";
        if (wrapGenerico) wrapGenerico.style.display = "block";
        renderRelatorioGenerico(relatorioAtivo);
      }
    });
  });
}

function setRelatorioMesAtual() {
  const hoje = new Date();
  (document.getElementById("relMensalAno") as HTMLSelectElement).value = String(hoje.getFullYear());
  (document.getElementById("relMensalMes") as HTMLSelectElement).value = String(hoje.getMonth() + 1);
  carregarRelatorioMensalDetalhado();
}

async function carregarRelatorioMensalDetalhado() {
  if (!currentUser) return;
  const ano = (document.getElementById("relMensalAno") as HTMLSelectElement)?.value || new Date().getFullYear();
  const mes = (document.getElementById("relMensalMes") as HTMLSelectElement)?.value || (new Date().getMonth() + 1);

  try {
    const data = await apiFetch(`/api/relatorios/mensal?ano=${ano}&mes=${mes}`);
    const kpis = data.kpis || {};

    // Populate KPI Cards
    (document.getElementById("rmFaturamento") as HTMLElement).textContent = brl(kpis.faturamentoBruto || 0);
    (document.getElementById("rmDescontosBadge") as HTMLElement).textContent = `Descontos: ${brl(kpis.totalDescontos || 0)}`;
    (document.getElementById("rmCmv") as HTMLElement).textContent = brl(kpis.cmv || 0);
    (document.getElementById("rmLucro") as HTMLElement).textContent = brl(kpis.lucroBruto || 0);
    (document.getElementById("rmMargem") as HTMLElement).textContent = `Margem Real: ${(kpis.margemPercentual || 0).toFixed(1)}%`;
    (document.getElementById("rmQtdVendas") as HTMLElement).textContent = String(kpis.qtdVendas || 0);
    (document.getElementById("rmTicketMedio") as HTMLElement).textContent = `Ticket Médio: ${brl(kpis.ticketMedio || 0)}`;

    const corTexto = getComputedStyle(document.body).getPropertyValue("--muted") || "#8a97a1";
    const corAccent = getComputedStyle(document.body).getPropertyValue("--accent") || "#2fbf8f";

    // 1. Daily Evolution Chart
    const ctxEvolucao = (document.getElementById("chartRelatorioMensalEvolucao") as HTMLCanvasElement)?.getContext("2d");
    if (ctxEvolucao && data.evolucaoDiaria) {
      if (chartRelMensalEvolucaoInstance) chartRelMensalEvolucaoInstance.destroy();

      chartRelMensalEvolucaoInstance = new Chart(ctxEvolucao, {
        type: "bar",
        data: {
          labels: data.evolucaoDiaria.map((d: any) => `Dia ${d.dia}`),
          datasets: [
            {
              label: "Faturamento (R$)",
              data: data.evolucaoDiaria.map((d: any) => d.faturamento),
              backgroundColor: corAccent,
              borderRadius: 4,
            },
            {
              label: "Lucro (R$)",
              data: data.evolucaoDiaria.map((d: any) => d.lucro),
              backgroundColor: "#5a8ce0",
              borderRadius: 4,
            },
          ],
        },
        options: {
          responsive: true,
          plugins: { legend: { labels: { color: corTexto } } },
          scales: {
            x: { ticks: { color: corTexto, font: { size: 10 } }, grid: { display: false } },
            y: { ticks: { color: corTexto, callback: (v: any) => `R$ ${v}` } },
          },
        },
      });
    }

    // 2. Payment Method Chart
    const ctxFormas = (document.getElementById("chartRelatorioMensalFormas") as HTMLCanvasElement)?.getContext("2d");
    if (ctxFormas && data.formasPagamento) {
      if (chartRelMensalFormasInstance) chartRelMensalFormasInstance.destroy();

      chartRelMensalFormasInstance = new Chart(ctxFormas, {
        type: "doughnut",
        data: {
          labels: data.formasPagamento.map((f: any) => f.forma),
          datasets: [{
            data: data.formasPagamento.map((f: any) => f.total),
            backgroundColor: ["#2fbf8f", "#5a8ce0", "#e0a53a", "#e05a4e"],
          }],
        },
        options: {
          responsive: true,
          plugins: {
            legend: { position: "bottom", labels: { color: corTexto, font: { size: 11 } } },
          },
        },
      });
    }

    // 3. Table: Sellers Performance
    const tbodyVendedores = document.getElementById("tbodyRmRankingVendedores");
    if (tbodyVendedores) {
      if (!data.rankingVendedores || data.rankingVendedores.length === 0) {
        tbodyVendedores.innerHTML = `<tr><td colspan="5" class="empty-state">Sem dados de vendedores no mês</td></tr>`;
      } else {
        tbodyVendedores.innerHTML = data.rankingVendedores.map((v: any) => `
          <tr>
            <td><strong>${v.nome}</strong></td>
            <td class="text-end">${v.qtd}</td>
            <td class="text-end fw-bold">${brl(v.total)}</td>
            <td class="text-end">${(v.participacao || 0).toFixed(1)}%</td>
            <td class="text-end" style="color:var(--accent);">${brl(v.comissaoTotal || 0)}</td>
          </tr>
        `).join("");
      }
    }

    // 4. Table: Categories Performance
    const tbodyCategorias = document.getElementById("tbodyRmCategorias");
    if (tbodyCategorias) {
      if (!data.desempenhoCategorias || data.desempenhoCategorias.length === 0) {
        tbodyCategorias.innerHTML = `<tr><td colspan="4" class="empty-state">Sem dados no mês</td></tr>`;
      } else {
        tbodyCategorias.innerHTML = data.desempenhoCategorias.map((c: any) => `
          <tr>
            <td><strong>${c.categoria}</strong></td>
            <td class="text-end">${c.qtd} un.</td>
            <td class="text-end fw-bold">${brl(c.faturamento)}</td>
            <td class="text-end text-success">${brl(c.lucro)}</td>
          </tr>
        `).join("");
      }
    }

    // 5. Table: Top 10 Products
    const tbodyTop = document.getElementById("tbodyRmTopProdutos");
    if (tbodyTop) {
      if (!data.topProdutos || data.topProdutos.length === 0) {
        tbodyTop.innerHTML = `<tr><td colspan="7" class="empty-state">Sem vendas de produtos registradas neste mês</td></tr>`;
      } else {
        tbodyTop.innerHTML = data.topProdutos.slice(0, 10).map((p: any, idx: number) => `
          <tr>
            <td><strong>#${idx + 1}</strong></td>
            <td><strong>${p.nome}</strong></td>
            <td>${p.marca || "-"}</td>
            <td class="text-end">${p.qtd}</td>
            <td class="text-end fw-bold">${brl(p.faturamento)}</td>
            <td class="text-end text-success">${brl(p.lucro)}</td>
            <td class="text-end">${(p.margemPercentual || 0).toFixed(1)}%</td>
          </tr>
        `).join("");
      }
    }
  } catch (err: any) {
    console.error("Erro no relatório mensal:", err);
  }
}

function renderRelatorioGenerico(tipo: string) {
  const el = document.getElementById("relatorioConteudoGenerico");
  if (!el) return;

  if (tipo === "produtos") {
    el.innerHTML = `
      <table class="table mb-0 align-middle">
        <thead><tr><th>Nome</th><th>Marca</th><th>Categoria</th><th class="text-end">Custo</th><th class="text-end">Venda</th><th class="text-end">Estoque</th></tr></thead>
        <tbody>
          ${produtos.map((p) => `
            <tr>
              <td>${p.nome}</td><td>${p.marca || "-"}</td><td>${p.categoria || "-"}</td>
              <td class="text-end">${brl(p.custo)}</td><td class="text-end fw-bold">${brl(p.venda)}</td>
              <td class="text-end">${p.estoque}</td>
            </tr>
          `).join("") || '<tr><td colspan="6" class="empty-state">Sem produtos</td></tr>'}
        </tbody>
      </table>
    `;
  } else if (tipo === "estoque") {
    el.innerHTML = `
      <table class="table mb-0 align-middle">
        <thead><tr><th>Produto</th><th class="text-end">Estoque</th><th class="text-end">Mínimo</th><th class="text-end">Custo</th><th class="text-end">Valor Total</th></tr></thead>
        <tbody>
          ${produtos.map((p) => `
            <tr>
              <td>${p.nome}</td><td class="text-end">${p.estoque}</td><td class="text-end">${p.minimo}</td>
              <td class="text-end">${brl(p.custo)}</td><td class="text-end fw-bold">${brl(p.estoque * p.custo)}</td>
            </tr>
          `).join("") || '<tr><td colspan="5" class="empty-state">Sem dados</td></tr>'}
        </tbody>
      </table>
    `;
  } else if (tipo === "devedores") {
    el.innerHTML = `
      <table class="table mb-0 align-middle">
        <thead><tr><th>Devedor</th><th>Telefone</th><th class="text-end">Saldo Devedor</th><th>Previsão</th></tr></thead>
        <tbody>
          ${devedores.map((d) => `
            <tr>
              <td>${d.nome}</td><td>${d.telefone || "-"}</td>
              <td class="text-end fw-bold text-danger">${brl(d.saldo_devedor || 0)}</td>
              <td>${d.data_prevista ? fmtData(d.data_prevista) : "-"}</td>
            </tr>
          `).join("") || '<tr><td colspan="4" class="empty-state">Nenhum devedor</td></tr>'}
        </tbody>
      </table>
    `;
  } else if (tipo === "vendas") {
    el.innerHTML = `
      <div class="p-3 text-muted">Use a aba <strong>Vendas</strong> para consultar o histórico completo com filtros por período detalhados.</div>
    `;
  }
}

function imprimirRelatorioAtual() {
  const lojaNome = (document.getElementById("topbarNome") as HTMLElement)?.textContent || "Loja de Suplementos";
  const printArea = document.getElementById("printArea");
  if (!printArea) return;

  if (relatorioAtivo === "mensal") {
    const ano = (document.getElementById("relMensalAno") as HTMLSelectElement).value;
    const mesText = (document.getElementById("relMensalMes") as HTMLSelectElement).selectedOptions[0].text;
    const fat = (document.getElementById("rmFaturamento") as HTMLElement).textContent;
    const luc = (document.getElementById("rmLucro") as HTMLElement).textContent;
    const cmv = (document.getElementById("rmCmv") as HTMLElement).textContent;
    const qtd = (document.getElementById("rmQtdVendas") as HTMLElement).textContent;

    printArea.innerHTML = `
      <div style="border-bottom:2px solid #333; padding-bottom:10px; margin-bottom:15px;">
        <h2 style="margin:0;">${lojaNome}</h2>
        <h4 style="margin:4px 0;">Relatório de Desempenho Mensal Detalhado - ${mesText} / ${ano}</h4>
        <small>Gerado em: ${new Date().toLocaleString("pt-BR")}</small>
      </div>

      <div style="display:flex; justify-content:space-between; margin-bottom:20px;">
        <div><strong>Faturamento:</strong> ${fat}</div>
        <div><strong>CMV:</strong> ${cmv}</div>
        <div><strong>Lucro Bruto:</strong> ${luc}</div>
        <div><strong>Qtd Vendas:</strong> ${qtd}</div>
      </div>

      <h5>Ranking de Vendedores no Mês</h5>
      ${document.getElementById("tabelaRmRankingVendedores")?.outerHTML || ""}

      <h5 style="margin-top:20px;">Top Produtos Mais Vendidos</h5>
      ${document.getElementById("tabelaRmTopProdutos")?.outerHTML || ""}

      <h5 style="margin-top:20px;">Faturamento por Categoria</h5>
      ${document.getElementById("tabelaRmCategorias")?.outerHTML || ""}
    `;
  } else {
    printArea.innerHTML = `
      <h3>${lojaNome} - Relatório de ${relatorioAtivo.toUpperCase()}</h3>
      <p>Gerado em: ${new Date().toLocaleString("pt-BR")}</p>
      ${document.getElementById("relatorioConteudoGenerico")?.innerHTML || ""}
    `;
  }

  window.print();
}

/* ========================================================================== */
/*                               CLIENTES                                     */
/* ========================================================================== */

async function carregarClientes() {
  if (!currentUser) return;
  try {
    clientes = await apiFetch("/api/clientes");
    renderClientesFiltrados();
    popularSelectClientesVenda();
  } catch (err: any) {
    console.error("Erro ao carregar clientes:", err);
  }
}

function renderClientesFiltrados() {
  const termo = ((document.getElementById("buscaCliente") as HTMLInputElement)?.value || "").toLowerCase().trim();
  const lista = clientes.filter((c) => !termo || `${c.nome} ${c.telefone || ""}`.toLowerCase().includes(termo));
  const tbody = document.getElementById("tbodyClientes");
  if (!tbody) return;

  if (lista.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="empty-state">Nenhum cliente encontrado</td></tr>`;
    return;
  }

  tbody.innerHTML = lista.map((c) => `
    <tr>
      <td><strong>${c.nome}</strong></td>
      <td>${c.telefone || "-"}</td>
      <td>${c.whatsapp || "-"}</td>
      <td class="text-end">${c.total_compras || 0}</td>
      <td class="text-end fw-bold">${brl(c.total_gasto || 0)}</td>
      <td class="text-center">
        <button class="btn btn-sm btn-outline-secondary" onclick="openClienteModal(${c.id})" title="Editar cliente">
          <i class="fa-solid fa-pen-to-square"></i>
        </button>
      </td>
    </tr>
  `).join("");
}

async function openClienteModal(id?: number) {
  (document.getElementById("clienteModalTitle") as HTMLElement).textContent = id ? "Editar Cliente" : "Novo Cliente";
  const btnExcluir = document.getElementById("btnExcluirCliente") as HTMLElement;
  const wrapHist = document.getElementById("cliHistoricoWrap") as HTMLElement;
  btnExcluir.style.display = id && currentUser?.role === "admin" ? "inline-block" : "none";
  wrapHist.style.display = id ? "block" : "none";

  if (id) {
    const c = clientes.find((x) => x.id === id);
    if (!c) return;
    (document.getElementById("cliId") as HTMLInputElement).value = String(c.id);
    (document.getElementById("cliNome") as HTMLInputElement).value = c.nome || "";
    (document.getElementById("cliTelefone") as HTMLInputElement).value = c.telefone || "";
    (document.getElementById("cliWhatsapp") as HTMLInputElement).value = c.whatsapp || "";

    try {
      const historico = await apiFetch(`/api/clientes/${id}/historico`);
      const wrap = document.getElementById("cliHistorico");
      if (wrap) {
        if (!historico || historico.length === 0) {
          wrap.innerHTML = `<div class="empty-state">Nenhuma compra registrada ainda</div>`;
        } else {
          wrap.innerHTML = historico.map((v: any) => `
            <div class="d-flex justify-content-between border-bottom py-1" style="font-size:13px;">
              <span>${fmtData(v.data)} — ${v.itens?.map((i: any) => i.nome).join(", ") || "Venda #" + v.id}</span>
              <strong>${brl(v.total)}</strong>
            </div>
          `).join("");
        }
      }
    } catch (e) {}
  } else {
    (document.getElementById("cliId") as HTMLInputElement).value = "";
    (document.getElementById("cliNome") as HTMLInputElement).value = "";
    (document.getElementById("cliTelefone") as HTMLInputElement).value = "";
    (document.getElementById("cliWhatsapp") as HTMLInputElement).value = "";
  }
  bootstrap.Modal.getOrCreateInstance(document.getElementById("modalCliente")).show();
}

async function salvarCliente() {
  const nome = (document.getElementById("cliNome") as HTMLInputElement).value.trim();
  if (!nome) {
    toast("Informe o nome do cliente", "warning");
    return;
  }
  const id = (document.getElementById("cliId") as HTMLInputElement).value;
  const dados = {
    nome,
    telefone: (document.getElementById("cliTelefone") as HTMLInputElement).value.trim(),
    whatsapp: (document.getElementById("cliWhatsapp") as HTMLInputElement).value.trim(),
  };

  try {
    if (id) {
      await apiFetch(`/api/clientes/${id}`, { method: "PUT", body: JSON.stringify(dados) });
      toast("Cliente atualizado");
    } else {
      await apiFetch("/api/clientes", { method: "POST", body: JSON.stringify(dados) });
      toast("Cliente cadastrado");
    }
    bootstrap.Modal.getInstance(document.getElementById("modalCliente"))?.hide();
    carregarClientes();
  } catch (err: any) {
    toast(err.message, "error");
  }
}

async function excluirCliente() {
  const id = (document.getElementById("cliId") as HTMLInputElement).value;
  if (!id) return;
  Swal.fire({
    title: "Excluir cliente?",
    icon: "warning",
    showCancelButton: true,
    confirmButtonText: "Excluir",
    confirmButtonColor: "#e05a4e",
    cancelButtonText: "Cancelar",
  }).then(async (r: any) => {
    if (r.isConfirmed) {
      try {
        await apiFetch(`/api/clientes/${id}`, { method: "DELETE" });
        bootstrap.Modal.getInstance(document.getElementById("modalCliente"))?.hide();
        toast("Cliente excluído");
        carregarClientes();
      } catch (err: any) {
        toast(err.message, "error");
      }
    }
  });
}

/* ========================================================================== */
/*                               DEVEDORES (FIADO)                            */
/* ========================================================================== */

async function carregarDevedores() {
  if (!currentUser) return;
  try {
    const data = await apiFetch("/api/devedores");
    devedores = data.devedores || [];
    const totalEl = document.getElementById("devTotalReceber");
    if (totalEl) totalEl.textContent = brl(data.totalReceber || 0);
    renderDevedoresFiltrados();
  } catch (err: any) {
    console.warn("Aviso ao carregar devedores:", err.message || err);
  }
}

function toggleFiltroPendentes() {
  filtroPendentes = !filtroPendentes;
  document.getElementById("btnFiltroPendentes")?.classList.toggle("active", filtroPendentes);
  renderDevedoresFiltrados();
}

function renderDevedoresFiltrados() {
  const termo = ((document.getElementById("devBusca") as HTMLInputElement)?.value || "").toLowerCase().trim();
  let lista = devedores.filter((d) => !termo || d.nome.toLowerCase().includes(termo));
  if (filtroPendentes) {
    lista = lista.filter((d) => (d.saldo_devedor || 0) > 0.01);
  }

  const tbody = document.getElementById("tbodyDevedores");
  if (!tbody) return;

  if (lista.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="empty-state">Nenhum devedor encontrado</td></tr>`;
    return;
  }

  tbody.innerHTML = lista.map((d) => {
    const saldo = d.saldo_devedor || 0;
    const status = saldo <= 0.01 ? `<span class="badge-pago">Quitado</span>` : `<span class="badge-pendente">Pendente</span>`;

    return `
      <tr>
        <td><strong>${d.nome}</strong></td>
        <td>${d.telefone || "-"}</td>
        <td class="text-end fw-bold ${saldo > 0 ? 'text-danger' : 'text-success'}">${brl(saldo)}</td>
        <td>${d.data_prevista ? fmtData(d.data_prevista) : "-"}</td>
        <td>${status}</td>
        <td class="text-center">
          <button class="btn btn-sm btn-outline-secondary" onclick="abrirDetalheDevedor(${d.id})" title="Gerenciar dívida / pagamentos">
            <i class="fa-solid fa-coins"></i>
          </button>
        </td>
      </tr>
    `;
  }).join("");
}

function openDevedorModal() {
  ["devNome", "devTelefone", "devValor", "devDataVenda", "devDataPrevista"].forEach((f) => {
    const el = document.getElementById(f) as HTMLInputElement;
    if (el) el.value = "";
  });
  (document.getElementById("devDataVenda") as HTMLInputElement).value = new Date().toISOString().slice(0, 10);
  bootstrap.Modal.getOrCreateInstance(document.getElementById("modalDevedor")).show();
}

async function salvarDevedor() {
  const nome = (document.getElementById("devNome") as HTMLInputElement).value.trim();
  const valor = parseFloat((document.getElementById("devValor") as HTMLInputElement).value) || 0;

  if (!nome || valor <= 0) {
    toast("Informe o nome e valor da dívida", "warning");
    return;
  }

  try {
    await apiFetch("/api/devedores", {
      method: "POST",
      body: JSON.stringify({
        nome,
        telefone: (document.getElementById("devTelefone") as HTMLInputElement).value.trim(),
        valor,
        dataVenda: (document.getElementById("devDataVenda") as HTMLInputElement).value,
        dataPrevista: (document.getElementById("devDataPrevista") as HTMLInputElement).value,
      }),
    });
    bootstrap.Modal.getInstance(document.getElementById("modalDevedor"))?.hide();
    toast("Devedor cadastrado com sucesso");
    carregarDevedores();
  } catch (err: any) {
    toast(err.message, "error");
  }
}

async function abrirDetalheDevedor(id: number) {
  try {
    const data = await apiFetch(`/api/devedores/${id}`);
    (document.getElementById("devDetalheId") as HTMLInputElement).value = String(id);
    (document.getElementById("devDetalheNome") as HTMLElement).textContent = data.devedor.nome;
    (document.getElementById("devDetalheSaldo") as HTMLElement).textContent = brl(data.saldo || 0);

    const wrapHist = document.getElementById("devHistoricoLista");
    if (wrapHist) {
      if (!data.movimentos || data.movimentos.length === 0) {
        wrapHist.innerHTML = `<div class="empty-state">Nenhum lançamento</div>`;
      } else {
        wrapHist.innerHTML = data.movimentos.map((m: any) => `
          <div class="d-flex justify-content-between border-bottom py-1" style="font-size:13px;">
            <span>${fmtData(m.data)} — ${m.tipo === "divida" ? "Dívida (+)" : "Pagamento (-)"} ${m.obs ? `(${m.obs})` : ""}</span>
            <strong class="${m.tipo === 'divida' ? 'text-danger' : 'text-success'}">${m.tipo === 'divida' ? '+' : '-'}${brl(m.valor)}</strong>
          </div>
        `).join("");
      }
    }
    bootstrap.Modal.getOrCreateInstance(document.getElementById("modalDevedorDetalhe")).show();
  } catch (err: any) {
    toast("Erro ao carregar detalhes do devedor", "error");
  }
}

async function devAdicionarDivida() {
  const id = (document.getElementById("devDetalheId") as HTMLInputElement).value;
  const valor = parseFloat((document.getElementById("devNovoValor") as HTMLInputElement).value) || 0;
  if (valor <= 0) {
    toast("Informe um valor positivo", "warning");
    return;
  }

  try {
    await apiFetch(`/api/devedores/${id}/movimento`, {
      method: "POST",
      body: JSON.stringify({ tipo: "divida", valor, obs: "Acréscimo manual de débito" }),
    });
    (document.getElementById("devNovoValor") as HTMLInputElement).value = "";
    abrirDetalheDevedor(parseInt(id));
    carregarDevedores();
  } catch (err: any) {
    toast(err.message, "error");
  }
}

async function devRegistrarPagamento() {
  const id = (document.getElementById("devDetalheId") as HTMLInputElement).value;
  const valor = parseFloat((document.getElementById("devNovoValor") as HTMLInputElement).value) || 0;
  if (valor <= 0) {
    toast("Informe um valor de pagamento", "warning");
    return;
  }

  try {
    await apiFetch(`/api/devedores/${id}/movimento`, {
      method: "POST",
      body: JSON.stringify({ tipo: "pagamento", valor, obs: "Pagamento parcial recebido" }),
    });
    (document.getElementById("devNovoValor") as HTMLInputElement).value = "";
    toast("Pagamento registrado");
    abrirDetalheDevedor(parseInt(id));
    carregarDevedores();
  } catch (err: any) {
    toast(err.message, "error");
  }
}

async function devQuitarTudo() {
  const id = (document.getElementById("devDetalheId") as HTMLInputElement).value;
  const saldoRaw = (document.getElementById("devDetalheSaldo") as HTMLElement).textContent || "0";

  Swal.fire({
    title: "Quitar débito total?",
    text: `Confirmar recebimento integral de ${saldoRaw}?`,
    icon: "question",
    showCancelButton: true,
    confirmButtonText: "Sim, quitar tudo",
    confirmButtonColor: "#2fbf8f",
    cancelButtonText: "Cancelar",
  }).then(async (r: any) => {
    if (r.isConfirmed) {
      try {
        const data = await apiFetch(`/api/devedores/${id}`);
        if (data.saldo <= 0) {
          toast("Dívida já se encontra quitada", "info");
          return;
        }
        await apiFetch(`/api/devedores/${id}/movimento`, {
          method: "POST",
          body: JSON.stringify({ tipo: "pagamento", valor: data.saldo, obs: "Quitação total de débitos" }),
        });
        toast("Dívida quitada com sucesso!");
        abrirDetalheDevedor(parseInt(id));
        carregarDevedores();
      } catch (err: any) {
        toast(err.message, "error");
      }
    }
  });
}

/* ========================================================================== */
/*                               VENDEDORES & COMISSÕES                       */
/* ========================================================================== */

async function carregarVendedores() {
  if (!currentUser) return;
  try {
    vendedores = await apiFetch("/api/vendedores");
    popularSelectVendedoresVenda();
    renderVendedores();
  } catch (err: any) {
    console.error("Erro ao carregar vendedores:", err);
  }
}

function renderVendedores() {
  const tbody = document.getElementById("tbodyVendedores");
  if (!tbody) return;

  if (vendedores.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty-state">Nenhum vendedor cadastrado</td></tr>`;
    return;
  }

  tbody.innerHTML = vendedores.map((v) => `
    <tr>
      <td><strong>${v.nome}</strong></td>
      <td class="text-end fw-bold">${(v.comissao_percentual || 0).toFixed(1)}%</td>
      <td><span class="badge ${v.ativo ? 'badge-pago' : 'badge-pendente'}">${v.ativo ? 'Ativo' : 'Inativo'}</span></td>
      <td class="text-center">
        <button class="btn btn-sm btn-outline-secondary" onclick="openVendedorModal(${v.id})" title="Editar vendedor">
          <i class="fa-solid fa-pen-to-square"></i>
        </button>
      </td>
    </tr>
  `).join("");
}

function openVendedorModal(id?: number) {
  (document.getElementById("vendedorModalTitle") as HTMLElement).textContent = id ? "Editar Vendedor" : "Novo Vendedor";
  const btnExcluir = document.getElementById("btnExcluirVendedor") as HTMLElement;
  btnExcluir.style.display = id ? "inline-block" : "none";

  if (id) {
    const v = vendedores.find((x) => x.id === id);
    if (!v) return;
    (document.getElementById("venId") as HTMLInputElement).value = String(v.id);
    (document.getElementById("venNome") as HTMLInputElement).value = v.nome || "";
    (document.getElementById("venComissao") as HTMLInputElement).value = String(v.comissao_percentual || 0);
    (document.getElementById("venAtivo") as HTMLInputElement).checked = v.ativo !== 0;
  } else {
    (document.getElementById("venId") as HTMLInputElement).value = "";
    (document.getElementById("venNome") as HTMLInputElement).value = "";
    (document.getElementById("venComissao") as HTMLInputElement).value = "5";
    (document.getElementById("venAtivo") as HTMLInputElement).checked = true;
  }
  bootstrap.Modal.getOrCreateInstance(document.getElementById("modalVendedor")).show();
}

async function salvarVendedor() {
  const nome = (document.getElementById("venNome") as HTMLInputElement).value.trim();
  if (!nome) {
    toast("Informe o nome do vendedor", "warning");
    return;
  }

  const id = (document.getElementById("venId") as HTMLInputElement).value;
  const dados = {
    nome,
    comissao_percentual: parseFloat((document.getElementById("venComissao") as HTMLInputElement).value) || 0,
    ativo: (document.getElementById("venAtivo") as HTMLInputElement).checked,
  };

  try {
    if (id) {
      await apiFetch(`/api/vendedores/${id}`, { method: "PUT", body: JSON.stringify(dados) });
      toast("Vendedor atualizado");
    } else {
      await apiFetch("/api/vendedores", { method: "POST", body: JSON.stringify(dados) });
      toast("Vendedor cadastrado com sucesso");
    }
    bootstrap.Modal.getInstance(document.getElementById("modalVendedor"))?.hide();
    carregarVendedores();
    carregarComissoes();
    if (currentUser?.role === "admin") carregarUsuarios();
  } catch (err: any) {
    toast(err.message, "error");
  }
}

async function excluirVendedor() {
  const id = (document.getElementById("venId") as HTMLInputElement).value;
  if (!id) return;
  Swal.fire({
    title: "Excluir vendedor?",
    text: "O vendedor será removido, mantendo o histórico de vendas vinculadas.",
    icon: "warning",
    showCancelButton: true,
    confirmButtonText: "Excluir",
    confirmButtonColor: "#e05a4e",
    cancelButtonText: "Cancelar",
  }).then(async (r: any) => {
    if (r.isConfirmed) {
      try {
        await apiFetch(`/api/vendedores/${id}`, { method: "DELETE" });
        bootstrap.Modal.getInstance(document.getElementById("modalVendedor"))?.hide();
        toast("Vendedor excluído");
        carregarVendedores();
        carregarComissoes();
        if (currentUser?.role === "admin") carregarUsuarios();
      } catch (err: any) {
        toast(err.message, "error");
      }
    }
  });
}

function setPeriodoComissoesMesAtual() {
  const hoje = new Date();
  const dInicio = new Date(hoje.getFullYear(), hoje.getMonth(), 1).toISOString().slice(0, 10);
  (document.getElementById("comFiltroDe") as HTMLInputElement).value = dInicio;
  (document.getElementById("comFiltroAte") as HTMLInputElement).value = hoje.toISOString().slice(0, 10);
  carregarComissoes();
}

async function carregarComissoes() {
  if (!currentUser) return;
  const de = (document.getElementById("comFiltroDe") as HTMLInputElement)?.value;
  const ate = (document.getElementById("comFiltroAte") as HTMLInputElement)?.value;

  const params = new URLSearchParams();
  if (de) params.set("de", de);
  if (ate) params.set("ate", ate);

  try {
    const data = await apiFetch(`/api/comissoes?${params.toString()}`);
    const linhas = data.linhas || [];
    const totalEl = document.getElementById("comTotalGeral");
    if (totalEl) totalEl.textContent = brl(data.totalGeralComissoes || 0);

    const tbody = document.getElementById("tbodyComissoes");
    if (!tbody) return;

    if (linhas.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" class="empty-state">Sem vendas registradas para o período</td></tr>`;
      return;
    }

    tbody.innerHTML = linhas.map((l: any) => `
      <tr>
        <td><strong>${l.nome}</strong></td>
        <td class="text-end">${l.qtdVendas}</td>
        <td class="text-end fw-bold">${brl(l.totalVendido)}</td>
        <td class="text-end">${(l.comissaoPercentual || 0).toFixed(1)}%</td>
        <td class="text-end fw-bold" style="color:var(--accent);">${brl(l.comissaoAPagar)}</td>
      </tr>
    `).join("");
  } catch (err: any) {
    console.warn("Aviso ao apurar comissões:", err.message || err);
  }
}

/* ========================================================================== */
/*                               GESTÃO DE USUÁRIOS                           */
/* ========================================================================== */

function toggleUsrComissaoField() {
  const role = (document.getElementById("usrRole") as HTMLSelectElement)?.value;
  const wrap = document.getElementById("usrComissaoWrap");
  if (wrap) {
    wrap.style.display = role === "vendedor" ? "block" : "none";
  }
}

async function carregarUsuarios() {
  if (currentUser?.role !== "admin") return;

  try {
    const users = await apiFetch("/api/auth/users");
    const tbody = document.getElementById("tbodyUsuarios");
    if (!tbody) return;

    tbody.innerHTML = users.map((u: any) => `
      <tr>
        <td><strong>${u.nome}</strong></td>
        <td><code>${u.username}</code></td>
        <td>${u.email}</td>
        <td>
          <span class="badge-role role-${u.role}">${u.role.toUpperCase()}</span>
          ${u.role === 'vendedor' ? `<span class="badge bg-light text-dark border ms-1">${(u.comissao_percentual || 5).toFixed(1)}% Com.</span>` : ''}
        </td>
        <td><span class="badge ${u.ativo ? 'badge-pago' : 'badge-pendente'}">${u.ativo ? 'Ativo' : 'Desativado'}</span></td>
        <td>${fmtData(u.created_at)}</td>
        <td class="text-center">
          <button class="btn btn-sm btn-outline-secondary" onclick="openEditarUsuarioModal(${u.id})" title="Editar usuário">
            <i class="fa-solid fa-user-pen"></i>
          </button>
        </td>
      </tr>
    `).join("");
  } catch (err: any) {
    console.error("Erro ao carregar usuários:", err);
  }
}

function openNovoUsuarioModal() {
  (document.getElementById("usuarioModalTitle") as HTMLElement).textContent = "Novo Usuário";
  (document.getElementById("usrId") as HTMLInputElement).value = "";
  (document.getElementById("usrUsername") as HTMLInputElement).value = "";
  (document.getElementById("usrUsername") as HTMLInputElement).disabled = false;
  (document.getElementById("usrNome") as HTMLInputElement).value = "";
  (document.getElementById("usrEmail") as HTMLInputElement).value = "";
  (document.getElementById("usrSenha") as HTMLInputElement).value = "";
  (document.getElementById("usrSenhaLabel") as HTMLElement).textContent = "Senha de Acesso *";
  (document.getElementById("usrSenhaDica") as HTMLElement).style.display = "none";
  (document.getElementById("usrRole") as HTMLSelectElement).value = "vendedor";
  (document.getElementById("usrComissao") as HTMLInputElement).value = "5";
  (document.getElementById("usrAtivo") as HTMLInputElement).checked = true;
  (document.getElementById("btnExcluirUsuario") as HTMLElement).style.display = "none";

  toggleUsrComissaoField();
  bootstrap.Modal.getOrCreateInstance(document.getElementById("modalUsuario")).show();
}

async function openEditarUsuarioModal(id: number) {
  try {
    const users = await apiFetch("/api/auth/users");
    const u = users.find((x: any) => x.id === id);
    if (!u) return;

    (document.getElementById("usuarioModalTitle") as HTMLElement).textContent = "Editar Usuário";
    (document.getElementById("usrId") as HTMLInputElement).value = String(u.id);
    (document.getElementById("usrUsername") as HTMLInputElement).value = u.username;
    (document.getElementById("usrUsername") as HTMLInputElement).disabled = true;
    (document.getElementById("usrNome") as HTMLInputElement).value = u.nome;
    (document.getElementById("usrEmail") as HTMLInputElement).value = u.email;
    (document.getElementById("usrSenha") as HTMLInputElement).value = "";
    (document.getElementById("usrSenhaLabel") as HTMLElement).textContent = "Nova Senha (opcional)";
    (document.getElementById("usrSenhaDica") as HTMLElement).style.display = "block";
    (document.getElementById("usrRole") as HTMLSelectElement).value = u.role;
    (document.getElementById("usrComissao") as HTMLInputElement).value = String(u.comissao_percentual !== undefined ? u.comissao_percentual : 5);
    (document.getElementById("usrAtivo") as HTMLInputElement).checked = u.ativo !== 0;

    toggleUsrComissaoField();

    const btnExcluir = document.getElementById("btnExcluirUsuario") as HTMLElement;
    btnExcluir.style.display = u.id === currentUser?.id ? "none" : "inline-block";

    bootstrap.Modal.getOrCreateInstance(document.getElementById("modalUsuario")).show();
  } catch (e) {}
}

async function salvarUsuario() {
  const id = (document.getElementById("usrId") as HTMLInputElement).value;
  const nome = (document.getElementById("usrNome") as HTMLInputElement).value.trim();
  const username = (document.getElementById("usrUsername") as HTMLInputElement).value.trim();
  const email = (document.getElementById("usrEmail") as HTMLInputElement).value.trim();
  const role = (document.getElementById("usrRole") as HTMLSelectElement).value;
  const comissao_percentual = parseFloat((document.getElementById("usrComissao") as HTMLInputElement).value) || 0;
  const ativo = (document.getElementById("usrAtivo") as HTMLInputElement).checked;
  const password = (document.getElementById("usrSenha") as HTMLInputElement).value.trim();

  if (!nome || !email) {
    toast("Preencha nome e e-mail", "warning");
    return;
  }

  try {
    if (id) {
      await apiFetch(`/api/auth/users/${id}`, {
        method: "PUT",
        body: JSON.stringify({ nome, email, role, ativo, password, comissao_percentual }),
      });
      toast("Usuário atualizado com sucesso");
    } else {
      if (!username || !password) {
        toast("Login e senha são obrigatórios para novo usuário", "warning");
        return;
      }
      await apiFetch("/api/auth/users", {
        method: "POST",
        body: JSON.stringify({ username, nome, email, role, password, comissao_percentual }),
      });
      toast("Usuário cadastrado com sucesso");
    }
    bootstrap.Modal.getInstance(document.getElementById("modalUsuario"))?.hide();
    carregarUsuarios();
    carregarVendedores();
    carregarComissoes();
  } catch (err: any) {
    toast(err.message, "error");
  }
}

async function excluirUsuario() {
  const id = (document.getElementById("usrId") as HTMLInputElement).value;
  if (!id) return;
  Swal.fire({
    title: "Excluir usuário?",
    text: "O acesso deste usuário será cancelado permanentemente.",
    icon: "warning",
    showCancelButton: true,
    confirmButtonText: "Sim, excluir",
    confirmButtonColor: "#e05a4e",
    cancelButtonText: "Cancelar",
  }).then(async (r: any) => {
    if (r.isConfirmed) {
      try {
        await apiFetch(`/api/auth/users/${id}`, { method: "DELETE" });
        bootstrap.Modal.getInstance(document.getElementById("modalUsuario"))?.hide();
        toast("Usuário excluído");
        carregarUsuarios();
        carregarVendedores();
        carregarComissoes();
      } catch (err: any) {
        toast(err.message, "error");
      }
    }
  });
}

/* ========================================================================== */
/*                               CONFIGURAÇÕES                                */
/* ========================================================================== */

async function carregarConfig() {
  try {
    const config = await apiFetch("/api/config");
    const nomeLoja = config.nomeLoja || "Loja de Suplementos";
    (document.getElementById("topbarNome") as HTMLElement).textContent = nomeLoja;
    (document.getElementById("cfgNomeLoja") as HTMLInputElement).value = nomeLoja;

    const logo = config.logo || "";
    const logoTop = document.getElementById("topbarLogo") as HTMLImageElement;
    const logoPrev = document.getElementById("cfgLogoPreview") as HTMLImageElement;

    if (logo) {
      logoTop.src = logo;
      logoTop.style.display = "block";
      logoPrev.src = logo;
      logoPrev.style.display = "block";
    } else {
      logoTop.style.display = "none";
      logoPrev.style.display = "none";
    }

    const switchOcultar = document.getElementById("cfgOcultarVendasVendedor") as HTMLInputElement;
    if (switchOcultar) {
      switchOcultar.checked = config.ocultarVendasVendedor === "1";
    }
    policies.ocultarVendasVendedor = config.ocultarVendasVendedor === "1";
  } catch (e) {}
}

function handleLogo(ev: any) {
  const file = ev.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (e: any) => {
    const img = new Image();
    img.onload = () => {
      const c = document.createElement("canvas");
      c.width = 80; c.height = 80;
      c.getContext("2d")?.drawImage(img, 0, 0, 80, 80);
      const dataUrl = c.toDataURL("image/png");
      const prev = document.getElementById("cfgLogoPreview") as HTMLImageElement;
      prev.src = dataUrl;
      prev.style.display = "block";
      (document.getElementById("topbarLogo") as HTMLImageElement).src = dataUrl;
      (document.getElementById("topbarLogo") as HTMLImageElement).style.display = "block";
      apiFetch("/api/config", { method: "POST", body: JSON.stringify({ logo: dataUrl }) });
    };
    img.src = e.target.result;
  };
  reader.readAsDataURL(file);
}

async function salvarConfig() {
  const nomeLoja = (document.getElementById("cfgNomeLoja") as HTMLInputElement).value.trim();
  try {
    await apiFetch("/api/config", { method: "POST", body: JSON.stringify({ nomeLoja }) });
    (document.getElementById("topbarNome") as HTMLElement).textContent = nomeLoja;
    toast("Configurações gravadas com sucesso");
  } catch (err: any) {
    toast(err.message, "error");
  }
}

async function salvarPoliticaVendedor() {
  const ocultar = (document.getElementById("cfgOcultarVendasVendedor") as HTMLInputElement).checked;
  try {
    await apiFetch("/api/config", {
      method: "POST",
      body: JSON.stringify({ ocultarVendasVendedor: ocultar ? "1" : "0" }),
    });
    policies.ocultarVendasVendedor = ocultar;
    aplicarPerfilUsuario();
    toast(`Política atualizada: Tela de vendas para vendedor ${ocultar ? 'OCULTA' : 'VISÍVEL'}`);
  } catch (err: any) {
    toast(err.message, "error");
  }
}

/* ========================================================================== */
/*                               BACKUP & RESTAURAÇÃO                         */
/* ========================================================================== */

async function exportarBackupJSON() {
  try {
    const backup = await apiFetch("/api/backup/export");
    const blob = new Blob([JSON.stringify(backup, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `backup_appvenda_sqlite_${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    toast("Cópia de segurança baixada com sucesso");
  } catch (err: any) {
    toast("Erro ao exportar backup", "error");
  }
}

async function importarBackupJSON(ev: any) {
  const file = ev.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = async (e: any) => {
    let parsed: any;
    try {
      parsed = JSON.parse(e.target.result);
    } catch (err) {
      toast("Arquivo JSON inválido", "error");
      ev.target.value = "";
      return;
    }

    Swal.fire({
      title: "Restaurar Banco de Dados?",
      text: "Todos os dados atuais do banco SQLite serão substituídos pelos registros deste backup.",
      icon: "warning",
      showCancelButton: true,
      confirmButtonText: "Sim, restaurar",
      confirmButtonColor: "#e05a4e",
      cancelButtonText: "Cancelar",
    }).then(async (r: any) => {
      if (r.isConfirmed) {
        try {
          const res = await apiFetch("/api/backup/import", {
            method: "POST",
            body: JSON.stringify(parsed),
          });
          toast(res.message || "Backup restaurado com sucesso!");
          carregarTudo();
        } catch (err: any) {
          toast(err.message, "error");
        }
      }
      ev.target.value = "";
    });
  };
  reader.readAsText(file);
}

/* ========================================================================== */
/*                       EXPOSIÇÃO DE MÉTODOS GLOBAIS                         */
/* ========================================================================== */

// Expose handlers required by HTML onclick attributes
Object.assign(window, {
  executarLogin,
  logoutUsuario,
  preencherLogin,
  preencherELogar,
  toggleMostrarSenhaLogin,
  restaurarCredenciaisPadrao,
  openUserMenuModal,
  openProdutoModal,
  salvarProduto,
  excluirProduto,
  openImportarExcelModal,
  handleExcelFileUpload,
  baixarModeloPlanilhaExcel,
  processarImportacaoExcel,
  calcMargem,
  handleFoto,
  renderProdutosFiltrados,
  toggleMovCampos,
  salvarMovimentacao,
  carregarEstoque,
  buscarProdutoVenda,
  adicionarAoCarrinho,
  removerDoCarrinho,
  limparCarrinho,
  alterarQtdCarrinho,
  atualizarCarrinho,
  toggleFiadoCampos,
  finalizarVenda,
  setPresetFiltroVendas,
  limparFiltroVendas,
  carregarVendasFiltradas,
  verReciboVenda,
  imprimirRecibo,
  cancelarVendaAtual,
  openClienteModal,
  salvarCliente,
  excluirCliente,
  renderClientesFiltrados,
  openDevedorModal,
  salvarDevedor,
  abrirDetalheDevedor,
  devAdicionarDivida,
  devRegistrarPagamento,
  devQuitarTudo,
  toggleFiltroPendentes,
  renderDevedoresFiltrados,
  openVendedorModal,
  salvarVendedor,
  excluirVendedor,
  setPeriodoComissoesMesAtual,
  carregarComissoes,
  setRelatorioMesAtual,
  carregarRelatorioMensalDetalhado,
  imprimirRelatorioAtual,
  openNovoUsuarioModal,
  openEditarUsuarioModal,
  toggleUsrComissaoField,
  salvarUsuario,
  excluirUsuario,
  handleLogo,
  salvarConfig,
  salvarPoliticaVendedor,
  exportarBackupJSON,
  importarBackupJSON,
  carregarDashboard,
});

// Close suggestions on outside click
document.addEventListener("click", (e: any) => {
  if (!e.target.closest("#vendaBusca") && !e.target.closest("#vendaSugestoes")) {
    const box = document.getElementById("vendaSugestoes");
    if (box) box.style.display = "none";
  }
});

/* ========================================================================== */
/*                               INICIALIZAÇÃO                                */
/* ========================================================================== */

document.addEventListener("DOMContentLoaded", () => {
  setupNavegacao();
  setupEstoqueTabs();
  setupRelatoriosTabs();

  // Set default filter date for fiado expected date (7 days ahead)
  const dtPrev = document.getElementById("vDataPrevista") as HTMLInputElement;
  if (dtPrev) {
    dtPrev.value = new Date(Date.now() + 7 * 86400000).toISOString().slice(0, 10);
  }

  // Set sales period default filter to "Mês atual" (sem disparar fetch imediato antes da autenticação)
  setPresetFiltroVendas("mesAtual", false);

  // Set default monthly report selector to current year/month
  const hoje = new Date();
  const selAno = document.getElementById("relMensalAno") as HTMLSelectElement;
  const selMes = document.getElementById("relMensalMes") as HTMLSelectElement;
  if (selAno) selAno.value = String(hoje.getFullYear());
  if (selMes) selMes.value = String(hoje.getMonth() + 1);

  // Check auth session
  verificarSessao();

  // Drag and drop support for Excel import
  const dropZone = document.getElementById("dropZoneExcel");
  const inputExcel = document.getElementById("inputArquivoExcel") as HTMLInputElement;
  if (dropZone && inputExcel) {
    dropZone.addEventListener("dragover", (e: DragEvent) => {
      e.preventDefault();
      dropZone.classList.add("border-primary", "bg-surface2");
    });
    dropZone.addEventListener("dragleave", () => {
      dropZone.classList.remove("border-primary", "bg-surface2");
    });
    dropZone.addEventListener("drop", (e: DragEvent) => {
      e.preventDefault();
      dropZone.classList.remove("border-primary", "bg-surface2");
      if (e.dataTransfer && e.dataTransfer.files.length > 0) {
        inputExcel.files = e.dataTransfer.files;
        handleExcelFileUpload({ target: inputExcel } as any);
      }
    });
  }
});
