/** DOM id of the error paragraph for a server field path such as "components[0].name". */
export const errorId = (path: string) => `ai-error-${path.replace(/[^a-zA-Z0-9]+/g, '-')}`;

/** aria-invalid plus an aria-describedby list joining the field's error id and any extra ids. */
export function describeField(path: string, errors: Record<string, string>, extraId?: string) {
    const error = errors[path];
    const ids = [error ? errorId(path) : '', extraId ?? ''].filter(Boolean).join(' ');
    return { 'aria-invalid': error ? true : undefined, 'aria-describedby': ids || undefined };
}
