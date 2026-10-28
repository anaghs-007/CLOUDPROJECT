const { validateTemplateSet, loadTemplates } = require('./adaptivePolicyEngine');

try {
  validateTemplateSet(loadTemplates());
  console.log('Template validation passed');
} catch (error) {
  console.error('Template validation failed:', error.message);
  process.exitCode = 1;
}
