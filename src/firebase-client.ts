import { initializeApp, getApps, getApp } from "firebase/app";
import {
  getFirestore,
  collection,
  onSnapshot,
  query,
  orderBy,
  Unsubscribe,
  DocumentData,
  Firestore,
} from "firebase/firestore";
import firebaseConfig from "../firebase-applet-config.json";

// Initialize Firebase JS SDK
const app = getApps().length === 0 ? initializeApp(firebaseConfig) : getApp();

const dbId =
  firebaseConfig.firestoreDatabaseId &&
  firebaseConfig.firestoreDatabaseId !== "(default)"
    ? firebaseConfig.firestoreDatabaseId
    : undefined;

export const firestoreClient: Firestore = dbId
  ? getFirestore(app, dbId)
  : getFirestore(app);

export interface ProductItem {
  id: number;
  nome: string;
  marca?: string;
  categoria?: string;
  sabor?: string;
  peso?: string;
  codigo_interno?: string;
  codigo_barras?: string;
  custo: number;
  venda: number;
  estoque: number;
  minimo: number;
  foto?: string;
  created_at?: string;
  updated_at?: string;
}

export interface InventoryMovementItem {
  id: number;
  produto_id: number;
  produto_nome?: string;
  produto_marca?: string;
  tipo: "entrada" | "saida" | "ajuste";
  qtd: number;
  qtd_anterior: number;
  qtd_nova: number;
  custo_unit?: number;
  motivo?: string;
  data: string;
  user_id?: number;
}

export type RealtimeStatus = "connected" | "syncing" | "error";

type StatusCallback = (status: RealtimeStatus, message?: string) => void;
const statusListeners: Set<StatusCallback> = new Set();

export function onRealtimeStatusChange(callback: StatusCallback): () => void {
  statusListeners.add(callback);
  return () => statusListeners.delete(callback);
}

function notifyStatus(status: RealtimeStatus, message?: string) {
  statusListeners.forEach((fn) => {
    try {
      fn(status, message);
    } catch (e) {
      console.error("[Realtime Status Error]", e);
    }
  });
}

/**
 * Real-time listener for the product catalog.
 * Any update (creation, edit, stock change, deletion) across all sessions is pushed in real-time.
 */
export function subscribeToProducts(
  onUpdate: (products: ProductItem[]) => void,
  onError?: (err: Error) => void
): Unsubscribe {
  try {
    notifyStatus("syncing", "Conectando ao catálogo de produtos...");
    const colRef = collection(firestoreClient, "produtos");
    const q = query(colRef);

    const unsubscribe = onSnapshot(
      q,
      (snapshot) => {
        const list: ProductItem[] = [];
        snapshot.forEach((doc) => {
          const d = doc.data() as DocumentData;
          list.push({
            id: Number(d.id || doc.id),
            nome: d.nome || "",
            marca: d.marca || "",
            categoria: d.categoria || "",
            sabor: d.sabor || "",
            peso: d.peso || "",
            codigo_interno: d.codigo_interno || "",
            codigo_barras: d.codigo_barras || "",
            custo: Number(d.custo || 0),
            venda: Number(d.venda || 0),
            estoque: Number(d.estoque || 0),
            minimo: Number(d.minimo || 5),
            foto: d.foto || "",
            created_at: d.created_at,
            updated_at: d.updated_at,
          });
        });

        // Alphabetical sort by product name
        list.sort((a, b) => a.nome.localeCompare(b.nome));

        notifyStatus("connected", "Catálogo sincronizado em tempo real");
        onUpdate(list);
      },
      (err) => {
        console.error("[Firestore Realtime Products Error]", err);
        notifyStatus("error", "Erro na sincronização de produtos");
        if (onError) onError(err);
      }
    );

    return unsubscribe;
  } catch (err: any) {
    console.error("[Firestore Subscribe Products Exception]", err);
    notifyStatus("error", err.message);
    return () => {};
  }
}

/**
 * Real-time listener for inventory movements (stock history).
 * Any stock movement recorded by any user is immediately reflected across all sessions.
 */
export function subscribeToInventoryMovements(
  onUpdate: (movements: InventoryMovementItem[]) => void,
  onError?: (err: Error) => void
): Unsubscribe {
  try {
    const colRef = collection(firestoreClient, "movimentacoes");
    const q = query(colRef, orderBy("data", "desc"));

    const unsubscribe = onSnapshot(
      q,
      (snapshot) => {
        const list: InventoryMovementItem[] = [];
        snapshot.forEach((doc) => {
          const d = doc.data() as DocumentData;
          list.push({
            id: Number(d.id || doc.id),
            produto_id: Number(d.produto_id),
            produto_nome: d.produto_nome || "",
            produto_marca: d.produto_marca || "",
            tipo: d.tipo as any,
            qtd: Number(d.qtd || 0),
            qtd_anterior: Number(d.qtd_anterior || 0),
            qtd_nova: Number(d.qtd_nova || 0),
            custo_unit: d.custo_unit !== undefined ? Number(d.custo_unit) : undefined,
            motivo: d.motivo || "",
            data: d.data || "",
            user_id: d.user_id ? Number(d.user_id) : undefined,
          });
        });

        onUpdate(list);
      },
      (err) => {
        console.error("[Firestore Realtime Inventory Error]", err);
        if (onError) onError(err);
      }
    );

    return unsubscribe;
  } catch (err: any) {
    console.error("[Firestore Subscribe Inventory Exception]", err);
    return () => {};
  }
}
