// Fixture: the shape a real extension has (definePluginEntry from openclaw/plugin-sdk,
// which the fixture deliberately does not import so the shim's loader can be tested).
function definePluginEntry(entry) {
  return entry;
}
var demo_search_default = definePluginEntry({
  id: "demo-search",
  name: "Demo Search",
  register(api) {
    api.registerTool("demo_search", { description: "Search the demo index" }, (args) => ({ hits: [], query: args.query }));
  },
});
export { demo_search_default as default };
