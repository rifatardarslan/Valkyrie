from valkyrie.modules.dynamic.memory import analyze_memory
import json
res = analyze_memory('tests/mock_maps.log', 'tests/mock_core.dmp')
print(json.dumps(res, indent=4))
