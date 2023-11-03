import axios, { AxiosError } from "axios";

export function isNil(value: unknown): value is null | undefined {
  return value === null || value === undefined;
}
export function convertStringToB64(content: string): string {
  const messageBytes = Buffer.from(content, "utf-8");
  const base64Message = messageBytes.toString("base64");
  return base64Message;
}

export function delay(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export const removeDuplicates = <T>(list: Array<T>): Array<T> => [...new Set(list)];

export const ensureValue = <T>(value: T | null | undefined, propertyName: string): T => {
  if (isNil(value)) throw new Error(`'${propertyName}' is required for script execution.`);
  return value;
};

export const ensureValueIsOneOf = <T extends string>(
  options: Array<T>,
  value: string | undefined,
  opts: { caseSensitive?: boolean } = {}
): T | undefined => {
  if (value === undefined) return undefined;
  const match = options.find((option) => {
    return opts.caseSensitive
      ? option === value
      : option.toLocaleLowerCase() === value.toLocaleLowerCase();
  });
  if (!isNil(match)) return match;
  throw new Error(`Invalid enum value '${value}'. Valid options are: ${options.join(", ")}.`);
};

export const ensureEnumValue = <
  T extends string,
  TEnumObject extends Record<string, T> = Record<string, T>
>(
  enumObject: TEnumObject,
  value: string | undefined
): T | undefined => {
  return ensureValueIsOneOf(Object.values(enumObject), value);
};

/*
Reference: https://stackoverflow.com/a/18650828
*/
export function formatBytes(bytes: number, decimals = 2) {
  if (bytes === 0) return "0 Bytes";

  const kilobyte = 1024;
  const fractionalDigits = decimals < 0 ? 0 : decimals;
  const sizes = ["Bytes", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"];

  const exponentialValue = Math.floor(Math.log(bytes) / Math.log(kilobyte));
  const count = Number.parseFloat(
    (bytes / Math.pow(kilobyte, exponentialValue)).toFixed(fractionalDigits)
  );
  const unit = sizes[exponentialValue];
  return `${count} ${unit}`;
}

export const obfuscateProperties = <T extends Record<string, unknown> = Record<string, unknown>>(
  dictionary: T,
  properties: Array<keyof T>,
  replacement = "*********"
) => {
  return Object.entries(dictionary).reduce<T>((accumulator, [key, value]) => {
    return {
      ...accumulator,
      [key]: properties.includes(key) ? replacement : value,
    };
  }, {} as T);
};

export const getEnvVariable = (name: string): string | null => {
  return process.env[name] || null;
};

export const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export const isUrlAvailable = async (url: string): Promise<boolean> => {
  let delay = 5000;
  let maxAttempts = 5;
  let attempts = 0;
  while (attempts < maxAttempts) {
    try {
      logger.info(`Attempt ${attempts + 1} of ${maxAttempts}...`);
      const response = await axios.get(url);
      if (response.status >= 200 && response.status < 300) {
        return true;
      }
    } catch (error) {
      if (error instanceof AxiosError) {
        logger.info(error);
        if (error.response && error.response.status < 500) {
          return true;
        }
      }
      attempts++;
      if (attempts < maxAttempts) await sleep(delay);
    }
  }

  return false;
};
