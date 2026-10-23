/**
 * Device-local persistence for imported datasets. IndexedDB is opened on the
 * first call, never at construction, so nothing touches it until the user
 * keeps an import. Nothing here reaches the network.
 */

const DB_VERSION = 1;
const DATASETS = 'datasets';
const RECORDS = 'records';

const done = (request) =>
  new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
const committed = (tx) =>
  new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = tx.onabort = () => reject(tx.error);
  });

/**
 * Create the IndexedDB-backed store.
 * @param {{indexedDB?: () => IDBFactory|undefined, name?: string}} [options]
 *   `indexedDB` is read lazily; tests pass a spy.
 * @returns {{saveDataset: Function, listDatasets: Function,
 *   getRecords: Function, deleteDataset: Function, close: Function}}
 */
export function createImportStore({
  indexedDB: factory = () => globalThis.indexedDB,
  name = 'gev-user-imports',
} = {}) {
  let opening = null;
  function db() {
    if (opening) return opening;
    const idb = factory();
    if (!idb?.open)
      return Promise.reject(
        new Error('IndexedDB is unavailable in this browser.'),
      );
    const request = idb.open(name, DB_VERSION);
    request.onupgradeneeded = () => {
      const d = request.result;
      d.createObjectStore(DATASETS, { keyPath: 'id' });
      d.createObjectStore(RECORDS, {
        keyPath: ['datasetId', 'id'],
      }).createIndex('datasetId', 'datasetId');
    };
    opening = done(request).catch((error) => {
      opening = null;
      throw error;
    });
    return opening;
  }
  async function run(stores, mode, work) {
    const tx = (await db()).transaction(stores, mode);
    work(tx);
    await committed(tx);
  }
  return {
    async saveDataset({ dataset, records }) {
      await run([DATASETS, RECORDS], 'readwrite', (tx) => {
        tx.objectStore(DATASETS).put(dataset);
        const store = tx.objectStore(RECORDS);
        for (const record of records)
          store.put({ ...record, datasetId: dataset.id });
      });
      return dataset;
    },
    async listDatasets() {
      let request;
      await run([DATASETS], 'readonly', (tx) => {
        request = tx.objectStore(DATASETS).getAll();
      });
      return request.result;
    },
    async getRecords(datasetId) {
      let request;
      await run([RECORDS], 'readonly', (tx) => {
        request = tx.objectStore(RECORDS).index('datasetId').getAll(datasetId);
      });
      return request.result.map(({ datasetId: _omit, ...record }) => record);
    },
    async deleteDataset(datasetId) {
      await run([DATASETS, RECORDS], 'readwrite', (tx) => {
        tx.objectStore(DATASETS).delete(datasetId);
        tx.objectStore(RECORDS).delete(
          globalThis.IDBKeyRange.bound([datasetId], [datasetId, []]),
        );
      });
    },
    close() {
      opening?.then((d) => d.close()).catch(() => {});
      opening = null;
    },
  };
}

/** The same interface in memory, for tests and browsers without IndexedDB. */
export function createMemoryImportStore() {
  const datasets = new Map();
  const records = new Map();
  return {
    async saveDataset({ dataset, records: list }) {
      datasets.set(dataset.id, structuredClone(dataset));
      records.set(dataset.id, structuredClone(list));
      return dataset;
    },
    async listDatasets() {
      return [...datasets.values()].map((d) => structuredClone(d));
    },
    async getRecords(datasetId) {
      return structuredClone(records.get(datasetId) ?? []);
    },
    async deleteDataset(datasetId) {
      datasets.delete(datasetId);
      records.delete(datasetId);
    },
    close() {},
  };
}

const SAVED_MARK = 'gev.userImports.saved';

/**
 * Keep, restore and delete imported GeoJSON files. A localStorage flag records
 * whether anything was kept, so a page load with nothing saved never opens
 * IndexedDB.
 * @param {{store?: object, createStore?: Function, storage?: Storage|null,
 *   decode: Function}} deps `decode(bytes, {file})` returns `{dataset, records}`.
 */
export function createImportLibrary({
  store = null,
  createStore = createImportStore,
  storage = globalThis.localStorage ?? null,
  decode,
  toFeatureCollection,
}) {
  const get = () => (store ??= createStore());
  const mark = (on) => {
    try {
      if (on) storage?.setItem(SAVED_MARK, '1');
      else storage?.removeItem(SAVED_MARK);
    } catch {
      // Storage can be disabled; the store still works for this session.
    }
  };
  return {
    hasSaved() {
      try {
        return storage?.getItem(SAVED_MARK) === '1';
      } catch {
        return false;
      }
    },
    /** Decode and keep one file; resolves with the stored dataset. */
    async save(file) {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const result = await decode(bytes, { file: String(file.name || 'file') });
      await get().saveDataset(result);
      mark(true);
      return result.dataset;
    },
    /** Rebuild kept datasets as GeoJSON files tagged with `gevDatasetId`. */
    async restore() {
      if (!this.hasSaved()) return [];
      const datasets = await get().listDatasets();
      if (!datasets.length) mark(false);
      const files = [];
      for (const dataset of datasets) {
        const records = await get().getRecords(dataset.id);
        const file = new File(
          [JSON.stringify(toFeatureCollection(records))],
          dataset.name,
          { type: 'application/geo+json' },
        );
        files.push(Object.assign(file, { gevDatasetId: dataset.id }));
      }
      return files;
    },
    async remove(datasetId) {
      await get().deleteDataset(datasetId);
      if (!(await get().listDatasets()).length) mark(false);
    },
  };
}
