import { fetcher } from "../../../core/lib/fetcher";
import { Logger } from "../../../core/logger";


// const origin = "https://dood.watch";
const origin = "https://myvidplay.com";

const headers: Record<string, string> = {
    "Accept": "*/*",
    "Accept-Encoding": "identity;q=1, *;q=0",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive",
    "origin": origin,
    "sec-ch-ua": '"Not:A-Brand";v="99", "Brave";v="145", "Chromium";v="145"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "Sec-Fetch-Dest": "video",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-Storage-Access": "none",
    "Sec-GPC": "1",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"
}

const logPrefix = "[doodstream]"

export const extractDoodstream = async (url: string) => {
    headers["referer"] = url;

    Logger.info(logPrefix, url);
    const id = url.split("/").reverse()[0];

    if (!id) {
        Logger.error(logPrefix, "failed to extract id from `url`!");
        return;
    }

    try {
        const data1 = await fetcher(`${origin}/e/${id}`, true, "dood", { headers, keepalive: true });

        if (!data1) {
            Logger.error("[doodstream] data1 not found!");
            return;
        }

        const { success: success1, status: status1, text: text1 } = data1;

        if (!success1) {
            Logger.error("[doodstream] Fetcher failed, status:", status1);
            return;
        }

        Bun.write(`./logs/${Date.now()}`, text1);

        return { sources: [], subtitles: [] };
    }
    catch (err) {
        Logger.error("[streamtape] Error occured:", err);
    }
}