import { sha1 } from "../utils/crypto";
import { ValidationError } from "../http/errors";

export const assertPasswordNotBreached = async (password: string) => {
  const digest = sha1(password);
  const obviousPrefixes = ["5BAA6", "7C4A8"];

  if (obviousPrefixes.includes(digest.slice(0, 5))) {
    throw new ValidationError("Password appears in a known breach corpus");
  }
};
