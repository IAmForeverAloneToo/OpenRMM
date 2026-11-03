package yara

// The dotnet module: the .NET metadata of a PE file, or of a process's main
// executable image in a memory scan. Field names and meanings follow
// YARA's dotnet module, classes and methods included.

func init() {
	version := structT(map[string]*ftype{"major": tInt, "minor": tInt, "build_number": tInt, "revision_number": tInt})
	method := structT(map[string]*ftype{
		"name": tStr, "visibility": tStr, "static": tInt, "virtual": tInt, "final": tInt, "abstract": tInt,
		"return_type": tStr, "number_of_parameters": tInt, "parameters": arrayT(structT(map[string]*ftype{"name": tStr, "type": tStr})),
		"number_of_generic_parameters": tInt, "generic_parameters": arrayT(tStr),
	})
	register(&module{
		name: "dotnet",
		t: structT(map[string]*ftype{
			"is_dotnet": tInt, "version": tStr, "module_name": tStr, "typelib": tStr,
			"number_of_streams": tInt, "streams": arrayT(structT(map[string]*ftype{"name": tStr, "offset": tInt, "size": tInt})),
			"number_of_guids": tInt, "guids": arrayT(tStr),
			"number_of_resources": tInt, "resources": arrayT(structT(map[string]*ftype{"offset": tInt, "length": tInt, "name": tStr})),
			"assembly":             structT(map[string]*ftype{"version": version, "name": tStr, "culture": tStr}),
			"number_of_modulerefs": tInt, "modulerefs": arrayT(tStr),
			"number_of_user_strings": tInt, "user_strings": arrayT(tStr),
			"number_of_assembly_refs": tInt,
			"assembly_refs":           arrayT(structT(map[string]*ftype{"version": version, "public_key_or_token": tStr, "name": tStr})),
			"number_of_constants":     tInt, "constants": arrayT(tStr),
			"number_of_field_offsets": tInt, "field_offsets": arrayT(tInt),
			"number_of_classes": tInt,
			"classes": arrayT(structT(map[string]*ftype{
				"fullname": tStr, "name": tStr, "namespace": tStr, "visibility": tStr, "type": tStr, "abstract": tInt, "sealed": tInt,
				"number_of_generic_parameters": tInt, "generic_parameters": arrayT(tStr),
				"number_of_base_types": tInt, "base_types": arrayT(tStr),
				"number_of_methods": tInt, "methods": arrayT(method),
			})),
		}),
		load: loadDotnet,
	})
}

func flag(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

func strArr(list []string) arr {
	out := arr{}
	for _, s := range list {
		out = append(out, s)
	}
	return out
}

func loadDotnet(e *evaluator) any {
	var p *peFile
	switch {
	case e.target.Image != nil:
		p = parsePE(e.target.Image.Data, true, e.target.Image.Base)
	case e.size >= 0 && len(e.blocks) == 1 && e.blocks[0].Base == 0:
		p = parsePE(e.blocks[0].Data, false, 0)
	}
	var n *netFile
	if p != nil {
		n = parseDotnet(p)
	}
	if n == nil {
		return obj{"is_dotnet": int64(0)}
	}
	root := obj{"is_dotnet": int64(1), "version": n.version}
	streams := arr{}
	for _, s := range n.streams {
		streams = append(streams, obj{"name": s.name, "offset": p.address(n.root + uint64(s.offset)), "size": int64(s.size)})
	}
	root["streams"], root["number_of_streams"] = streams, int64(len(streams))
	guids := n.guidList()
	root["guids"], root["number_of_guids"] = strArr(guids), int64(len(guids))
	if n.rows(tModule) > 0 {
		root["module_name"] = n.str(n.cell(tModule, 1, 1))
	}
	if n.rows(tAssembly) > 0 {
		root["assembly"] = obj{
			"version": obj{
				"major": int64(n.cell(tAssembly, 1, 1)), "minor": int64(n.cell(tAssembly, 1, 2)),
				"build_number": int64(n.cell(tAssembly, 1, 3)), "revision_number": int64(n.cell(tAssembly, 1, 4)),
			},
			"name": n.str(n.cell(tAssembly, 1, 7)), "culture": n.str(n.cell(tAssembly, 1, 8)),
		}
	}
	if tl := n.typelib(); tl != "" {
		root["typelib"] = tl
	}
	res := arr{}
	for _, r := range n.resources() {
		res = append(res, obj{"offset": r.offset, "length": r.length, "name": r.name})
	}
	root["resources"], root["number_of_resources"] = res, int64(len(res))
	mods := n.moduleRefs()
	root["modulerefs"], root["number_of_modulerefs"] = strArr(mods), int64(len(mods))
	us := n.userStrings()
	root["user_strings"], root["number_of_user_strings"] = strArr(us), int64(len(us))
	refs := arr{}
	for _, r := range n.assemblyRefs() {
		refs = append(refs, obj{
			"version":             obj{"major": r.version[0], "minor": r.version[1], "build_number": r.version[2], "revision_number": r.version[3]},
			"public_key_or_token": r.token, "name": r.name,
		})
	}
	root["assembly_refs"], root["number_of_assembly_refs"] = refs, int64(len(refs))
	consts := n.constants()
	root["constants"], root["number_of_constants"] = strArr(consts), int64(len(consts))
	offsets := arr{}
	for _, o := range n.fieldOffsets() {
		offsets = append(offsets, o)
	}
	root["field_offsets"], root["number_of_field_offsets"] = offsets, int64(len(offsets))
	classes := arr{}
	for _, c := range n.classes() {
		methods := arr{}
		for _, m := range c.methods {
			params := arr{}
			for _, p := range m.params {
				params = append(params, obj{"name": p.name, "type": p.typ})
			}
			methods = append(methods, obj{
				"name": m.name, "visibility": m.visibility, "static": flag(m.static), "virtual": flag(m.virtual),
				"final": flag(m.final), "abstract": flag(m.abstract), "return_type": m.ret,
				"number_of_parameters": int64(len(params)), "parameters": params,
				"number_of_generic_parameters": int64(len(m.generics)), "generic_parameters": strArr(m.generics),
			})
		}
		classes = append(classes, obj{
			"fullname": c.fullname, "name": c.name, "namespace": c.namespace, "visibility": c.visibility, "type": c.kind,
			"abstract": flag(c.abstract), "sealed": flag(c.sealed),
			"number_of_generic_parameters": int64(len(c.generics)), "generic_parameters": strArr(c.generics),
			"number_of_base_types": int64(len(c.bases)), "base_types": strArr(c.bases),
			"number_of_methods": int64(len(methods)), "methods": methods,
		})
	}
	root["classes"], root["number_of_classes"] = classes, int64(len(classes))
	return root
}
