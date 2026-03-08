// common mapping routes — not tied to any provider, just AniZip lookups
// accessible at /mappings  from the root

import Elysia from "elysia";
import { AniZip } from "../anizip";

const mappingRoutes = new Elysia()
  // cross-platform ID mappings (MAL, AniList, TMDB, IMDB, Kitsu, etc.)
  .get("/mappings", async ({ query }) => {
    const malId = query?.mal_id ? parseInt(String(query.mal_id), 10) : undefined;
    const anilistId = query?.anilist_id
      ? parseInt(String(query.anilist_id), 10)
      : undefined;

    if (!malId && !anilistId) {
      return { error: "Provide mal_id or anilist_id query parameter" };
    }

    const mappings = await AniZip.getMappings({ mal_id: malId, anilist_id: anilistId });
    if (!mappings) {
      return { error: "No mappings found for the given ID" };
    }
    return mappings;
  }, {
    detail: { 
      tags: ['core'], 
      summary: 'Get Cross-Platform ID Mappings (MAL, AniList, etc.)' 
    }
  });

export { mappingRoutes };