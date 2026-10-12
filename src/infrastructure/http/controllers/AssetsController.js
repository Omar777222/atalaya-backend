import { validateSearch } from '../validators.js';

export class AssetsController {
  constructor({ searchAssets }) {
    this.searchAssets = searchAssets;
  }

  search = async (req, res, next) => {
    try {
      const query = validateSearch(req.query);
      res.json(await this.searchAssets.execute({ query }));
    } catch (err) {
      next(err);
    }
  };
}
