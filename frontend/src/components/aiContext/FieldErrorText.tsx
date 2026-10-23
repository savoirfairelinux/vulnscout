import { errorId } from "./fieldErrors";
import { ERROR } from "./styles";

function FieldErrorText({ path, errors }: Readonly<{ path: string; errors: Record<string, string> }>) {
    const error = errors[path];
    return error ? <p id={errorId(path)} className={`${ERROR} mt-1`}>{error}</p> : null;
}

export default FieldErrorText;
