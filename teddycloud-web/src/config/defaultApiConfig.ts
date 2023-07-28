import { Configuration } from "../api";

export const defaultAPIConfig = () =>
  new Configuration({
    basePath: process.env.TEDDYCLOUD_API_URL,
    //fetchApi: fetch,
  });
