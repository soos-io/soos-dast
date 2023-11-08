import { isNil } from "@soos-io/api-client/dist/utilities";

export const ensureEnumValue = <T, TEnumObject extends Record<string, T> = Record<string, T>>(
  enumObject: TEnumObject,
  inputValue: string | null | undefined,
  ignoreCase = true
): T | undefined => {
  if (isNil(inputValue)) {
    return undefined;
  }

  const options = Object.entries(enumObject) as unknown as Array<[string, string | number]>;
  const option = options.find(([, value]) => {
    const stringValue = value.toLocaleString();
    return ignoreCase
      ? stringValue.toLocaleLowerCase() === inputValue.toLocaleLowerCase()
      : stringValue === inputValue;
  });

  if (isNil(option)) {
    throw new Error(
      `Invalid enum value '${inputValue}'. Valid options are: ${options
        .map(([, value]) => value)
        .join(", ")}.`
    );
  }

  const [key] = option;
  return enumObject[key] as unknown as T;
};

export const getEnumValue = <T, TEnumObject extends Record<string, T> = Record<string, T>>(
  enumObject: TEnumObject,
  inputValue: string | null | undefined,
  ignoreCase = true
): T | undefined => {
  try {
    return ensureEnumValue(enumObject, inputValue, ignoreCase);
  } catch (error) {
    throw error;
  }
};
