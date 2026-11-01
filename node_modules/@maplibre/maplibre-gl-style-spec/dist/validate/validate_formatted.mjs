import { validateExpression } from "./validate_expression.mjs";
import { validateString } from "./validate_string.mjs";
// src/validate/validate_formatted.ts
function validateFormatted(options) {
	if (validateString(options).length === 0) return [];
	return validateExpression(options);
}
export { validateFormatted };

//# sourceMappingURL=validate_formatted.mjs.map