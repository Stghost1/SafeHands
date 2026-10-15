/**
 * Small IndexedDB wrapper for non-sensitive app preferences and reminders.
 * Raw symptom and scam text is deliberately never written here.
 *
 * Older web views and jsdom may not expose IndexedDB, so callers can use the
 * synchronous localStorage fallback while writes are mirrored when available.
 */
const DATABASE_NAME = "safehands-local";
const DATABASE_VERSION = 1;
const STORE_NAME = "settings";

function getIndexedDb(): IDBFactory | undefined {
  return typeof globalThis.indexedDB === "undefined" ? undefined : globalThis.indexedDB;
}

function openDatabase(): Promise<IDBDatabase | undefined> {
  const indexedDb = getIndexedDb();
  if (!indexedDb) return Promise.resolve(undefined);

  return new Promise((resolve) => {
    try {
      const request = indexedDb.open(DATABASE_NAME, DATABASE_VERSION);
      request.onupgradeneeded = () => {
        if (!request.result.objectStoreNames.contains(STORE_NAME)) {
          request.result.createObjectStore(STORE_NAME);
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => resolve(undefined);
      request.onblocked = () => resolve(undefined);
    } catch {
      resolve(undefined);
    }
  });
}

export async function saveLocalSetting<T>(key: string, value: T): Promise<void> {
  const database = await openDatabase();
  if (!database) return;
  await new Promise<void>((resolve) => {
    try {
      const transaction = database.transaction(STORE_NAME, "readwrite");
      transaction.objectStore(STORE_NAME).put(value, key);
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => resolve();
      transaction.onabort = () => resolve();
    } catch {
      resolve();
    }
  });
  database.close();
}

export async function readLocalSetting<T>(key: string): Promise<T | undefined> {
  const database = await openDatabase();
  if (!database) return undefined;
  return new Promise<T | undefined>((resolve) => {
    try {
      const request = database.transaction(STORE_NAME, "readonly").objectStore(STORE_NAME).get(key);
      request.onsuccess = () => {
        database.close();
        resolve(request.result as T | undefined);
      };
      request.onerror = () => {
        database.close();
        resolve(undefined);
      };
    } catch {
      database.close();
      resolve(undefined);
    }
  });
}

export async function clearLocalSettings(): Promise<void> {
  const database = await openDatabase();
  if (!database) return;
  await new Promise<void>((resolve) => {
    try {
      const transaction = database.transaction(STORE_NAME, "readwrite");
      transaction.objectStore(STORE_NAME).clear();
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => resolve();
      transaction.onabort = () => resolve();
    } catch {
      resolve();
    }
  });
  database.close();
}
