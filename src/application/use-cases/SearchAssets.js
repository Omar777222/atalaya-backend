export class SearchAssets {
  constructor({ assetCatalog }) {
    this.assetCatalog = assetCatalog;
  }

  async execute({ query }) {
    const items = await this.assetCatalog.search(query);
    return { query, total: items.length, items };
  }
}
