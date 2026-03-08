import Elysia from "elysia";
import { parseId, resolveId, getBestTitle } from "../../core/idResolver";
import { getAnimeProvider, isValidAnimeProvider, SUPPORTED_ANIME_PROVIDERS } from "./registry";
import { resolveToProviderNativeId } from "./common/resolver";

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, Range",
  "Access-Control-Expose-Headers": "Content-Length, Content-Range",
};

const animeRoutes = new Elysia({ prefix: "/anime" })
  
  // ─── Overview Endpoint ────────────────────────────────────────────────────────
  .get("/", () => ({
    service: "anime",
    description: "Unified anime API — provider-isolated route architecture",
    idFormats: {
      default: "AniList ID (bare number)",
      prefixes: ["mal:", "tmdb:", "imdb:", "kitsu:", "anidb:", "anisearch:", "livechart:", "internal:"],
      native: "Provider-native UUID (e.g., 78e38106-d9f3-a8b5-7974-9702f603dc9 or one-piece-100)",
    },
    providers: [...SUPPORTED_ANIME_PROVIDERS],
    endpoints: [
      "GET /anime/:id                     → cross-platform metadata & mappings (add ?full for raw AniZip)",
      "GET /anime/:id/:provider           → anime info from provider",
      "GET /anime/:id/:provider/episodes  → episode list from provider",
      "GET /anime/:id/:provider/episode/:ep → streams for episode from provider",
      "GET /anime/search/:query           → search (query param: provider)",
      "GET /anime/latest                  → latest releases with all mappings (query param: provider)",
    ],
  }), {
    detail: { tags: ['anime'], summary: 'API Overview & Supported Providers' }
  })

  // ─── Search Endpoint ──────────────────────────────────────────────────────────
  .get("/search/:query", async ({ params: { query }, query: qs }) => {
    const providerName = (qs?.provider as string) || "animepahe";
    if (!isValidAnimeProvider(providerName)) {
      return { error: `Unknown provider '${providerName}'. Supported: ${SUPPORTED_ANIME_PROVIDERS.join(", ")}` };
    }

    const provider = getAnimeProvider(providerName);
    const results = await provider.search(query);

    if (!Array.isArray(results)) {
      return results;
    }

    const enriched = await Promise.all((results as Record<string, unknown>[]).map(async (item) => {
      const { title, id, ...rest } = item;
      const result: Record<string, unknown> = { id, ...rest };
      
      if (title !== undefined && title !== null) {
        result.title = title;
      }
      
      // Use provider's native ID to get cross-platform mappings
      if (id && typeof id === "string" && provider && "getMappingsAndName" in provider && typeof (provider as any).getMappingsAndName === "function") {
        try {
          const mappingsData = await (provider as any).getMappingsAndName(id);
          if (mappingsData?.mappings) {
            const { mal_id, anilist_id, themoviedb_id, imdb_id, thetvdb_id, kitsu_id, anidb_id, anisearch_id, livechart_id, animeplanet_id, notifymoe_id } = mappingsData.mappings;
            if (mal_id !== null) result.mal_id = mal_id;
            if (anilist_id !== null) result.anilist_id = anilist_id;
            if (themoviedb_id !== null) result.themoviedb_id = themoviedb_id;
            if (imdb_id !== null) result.imdb_id = imdb_id;
            if (thetvdb_id !== null) result.thetvdb_id = thetvdb_id;
            if (kitsu_id !== null) result.kitsu_id = kitsu_id;
            if (anidb_id !== null) result.anidb_id = anidb_id;
            if (anisearch_id !== null) result.anisearch_id = anisearch_id;
            if (livechart_id !== null) result.livechart_id = livechart_id;
            if (animeplanet_id !== null) result.animeplanet_id = animeplanet_id;
            if (notifymoe_id !== null) result.notifymoe_id = notifymoe_id;
          }
        } catch { /* fallback without mappings */ }
      }

      return result;
    }));

    return { [providerName]: { provider: providerName, results: enriched } };
  }, {
    detail: { tags: ['anime'], summary: 'Search Anime by Title' }
  })

  // ─── Latest Endpoint ──────────────────────────────────────────────────────────
  .get("/latest", async ({ query: qs }) => {
    const providerName = (qs?.provider as string) || "animepahe";
    if (!isValidAnimeProvider(providerName)) {
      return { error: `Unknown provider '${providerName}'. Supported: ${SUPPORTED_ANIME_PROVIDERS.join(", ")}` };
    }

    const provider = getAnimeProvider(providerName);
    const latest = await provider.latest();

    if (!Array.isArray(latest)) {
      return latest;
    }

    const enriched = await Promise.all((latest as Record<string, unknown>[]).map(async (item) => {
      const { title, id, ...rest } = item;
      const result: Record<string, unknown> = { id, ...rest };
      
      // Always include title if present
      if (title !== undefined && title !== null) {
        result.title = title;
      }
      
      // Use provider's native ID to get cross-platform mappings
      if (id && typeof id === "string" && provider && "getMappingsAndName" in provider && typeof (provider as any).getMappingsAndName === "function") {
        try {
          const mappingsData = await (provider as any).getMappingsAndName(id);
          if (mappingsData?.mappings) {
            const { mal_id, anilist_id, themoviedb_id, imdb_id, thetvdb_id, kitsu_id, anidb_id, anisearch_id, livechart_id, animeplanet_id, notifymoe_id } = mappingsData.mappings;
            if (mal_id !== null) result.mal_id = mal_id;
            if (anilist_id !== null) result.anilist_id = anilist_id;
            if (themoviedb_id !== null) result.themoviedb_id = themoviedb_id;
            if (imdb_id !== null) result.imdb_id = imdb_id;
            if (thetvdb_id !== null) result.thetvdb_id = thetvdb_id;
            if (kitsu_id !== null) result.kitsu_id = kitsu_id;
            if (anidb_id !== null) result.anidb_id = anidb_id;
            if (anisearch_id !== null) result.anisearch_id = anisearch_id;
            if (livechart_id !== null) result.livechart_id = livechart_id;
            if (animeplanet_id !== null) result.animeplanet_id = animeplanet_id;
            if (notifymoe_id !== null) result.notifymoe_id = notifymoe_id;
          }
        } catch { /* fallback without mappings */ }
      }

      return result;
    }));

    return { [providerName]: { provider: providerName, results: enriched } };
  }, {
    detail: { tags: ['anime'], summary: 'Get Latest Anime Releases' }
  })

  // ─── Metadata Endpoint ────────────────────────────────────────────────────────
  .get("/:id", async ({ params: { id }, query }) => {
    const resolved = await resolveId(id);

    if (!resolved) {
      return { error: `Failed to resolve ID '${id}'` };
    }

    if (!resolved.mappings && resolved.parsedId.type !== "native") {
      return { error: `No mappings found for '${id}'` };
    }

    const isFull = query?.full === "true" || query?.full === "1";

    if (isFull && resolved.fullData) {
      return {
        id: resolved.parsedId.raw,
        idType: resolved.parsedId.type,
        full: resolved.fullData,
      };
    }

    return {
      id: resolved.parsedId.raw,
      idType: resolved.parsedId.type,
      mappings: resolved.mappings,
      titles: resolved.titles,
      bestTitle: getBestTitle(resolved.titles),
      providers: [...SUPPORTED_ANIME_PROVIDERS],
      episodeCount: resolved.fullData?.episodeCount ?? null,
      images: resolved.fullData?.images ?? [],
    };
  }, {
    detail: { tags: ['anime'], summary: 'Get Cross-Platform Metadata & Mappings' }
  })

  // ─── Provider Info Endpoint ───────────────────────────────────────────────────
  .get("/:id/:provider", async ({ params: { id, provider: providerName } }) => {
    if (!isValidAnimeProvider(providerName)) {
      return { error: `Unknown provider '${providerName}'. Supported: ${SUPPORTED_ANIME_PROVIDERS.join(", ")}` };
    }

    const parsed = parseId(id);
    const resolved = await resolveId(id);
    const mappings = resolved?.mappings ?? null;

    const provider = getAnimeProvider(providerName);
    const nativeId = await resolveToProviderNativeId(parsed, mappings, provider);
    if (!nativeId) {
      return { error: `Could not resolve '${id}' to a ${providerName} anime` };
    }

    const info = await provider.info(nativeId);
    if (!info) {
      return { error: `Anime not found on ${providerName}` };
    }

    return info;
  }, {
    detail: { tags: ['anime'], summary: 'Get Anime Info from Specific Provider' }
  })

  // ─── Episodes List Endpoint ───────────────────────────────────────────────────
  .get("/:id/:provider/episodes", async ({ params: { id, provider: providerName } }) => {
    if (!isValidAnimeProvider(providerName)) {
      return { error: `Unknown provider '${providerName}'. Supported: ${SUPPORTED_ANIME_PROVIDERS.join(", ")}` };
    }

    const parsed = parseId(id);
    const resolved = await resolveId(id);
    const mappings = resolved?.mappings ?? null;

    const provider = getAnimeProvider(providerName);
    const nativeId = await resolveToProviderNativeId(parsed, mappings, provider);
    if (!nativeId) {
      return { error: `Could not resolve '${id}' to a ${providerName} anime` };
    }

    const info = await provider.info(nativeId);
    if (!info) {
      return { error: `Anime not found on ${providerName}` };
    }

    return {
      id: info.id,
      name: info.name,
      mappings: info.mappings,
      episodeCount: info.episodes.length,
      episodes: info.episodes,
    };
  }, {
    detail: { tags: ['anime'], summary: 'Get Episode List from Provider' }
  })

  // ─── Streaming Links Endpoint ─────────────────────────────────────────────────
  .get("/:id/:provider/episode/:ep", async ({ params: { id, provider: providerName, ep } }) => {
    if (!isValidAnimeProvider(providerName)) {
      return { error: `Unknown provider '${providerName}'. Supported: ${SUPPORTED_ANIME_PROVIDERS.join(", ")}` };
    }

    const episodeNumber = parseInt(ep, 10);
    if (isNaN(episodeNumber) || episodeNumber < 1) {
      return { error: `Invalid episode number '${ep}'` };
    }

    const parsed = parseId(id);
    const resolved = await resolveId(id);
    const mappings = resolved?.mappings ?? null;

    const provider = getAnimeProvider(providerName);
    const nativeId = await resolveToProviderNativeId(parsed, mappings, provider);
    if (!nativeId) {
      return { error: `Could not resolve '${id}' to a ${providerName} anime` };
    }

    const session = await provider.getEpisodeSession(nativeId, episodeNumber);
    if (!session) {
      return { error: `Episode ${episodeNumber} not found on ${providerName}` };
    }

    const [results, animeData] = await Promise.all([
      provider.streams(nativeId, session),
      provider.getMappingsAndName(nativeId),
    ]);

    const finalMappings = animeData?.mappings ?? mappings;

    return {
      episode: episodeNumber,
      animeName: animeData?.name ?? getBestTitle(resolved?.titles ?? {}),
      mappings: finalMappings,
      corsHeaders: CORS_HEADERS,
      streams: results.map((stream) => {
        const { mappings: _, corsHeaders: __, ...rest } = stream as Record<string, unknown>;
        return rest;
      }),
    };
  }, {
    detail: { tags: ['anime'], summary: 'Get Streaming Links for Episode' }
  });

export { animeRoutes };