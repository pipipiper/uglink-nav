export async function load(url, context, nextLoad) {
  if (url.endsWith('/liquidglass.txt')) {
    return { format: 'module', shortCircuit: true, source: 'export default "";' };
  }
  return nextLoad(url, context);
}
