import { ValidationError } from "../http/errors";

export const verifyCaptchaToken = async (captchaToken?: string) => {
  const secret = process.env.TURNSTILE_SECRET;

  if (!secret) {
    return;
  }

  if (!captchaToken) {
    throw new ValidationError("Captcha verification is required");
  }

  const response = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      secret,
      response: captchaToken,
    }),
  });

  const result = (await response.json()) as { success?: boolean };

  if (!result.success) {
    throw new ValidationError("Captcha verification failed");
  }
};
