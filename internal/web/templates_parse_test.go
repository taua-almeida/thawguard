package web

import (
	"testing"
	"text/template/parse"
)

// TestTemplateReferencesResolve fails when any file-based template invokes a
// define that does not exist in the parsed set. html/template only surfaces a
// missing define at execution time, so without this check a typo in a
// {{ template "..." }} call ships silently and renders a blank region.
func TestTemplateReferencesResolve(t *testing.T) {
	defined := make(map[string]bool)
	for _, tmpl := range pageTemplates.Templates() {
		defined[tmpl.Name()] = true
	}
	for _, tmpl := range pageTemplates.Templates() {
		if tmpl.Tree == nil || tmpl.Tree.Root == nil {
			continue
		}
		walkTemplateNodes(tmpl.Tree.Root, func(name string) {
			if !defined[name] {
				t.Errorf("template %q references undefined template %q", tmpl.Name(), name)
			}
		})
	}
}

func walkTemplateNodes(node parse.Node, visit func(name string)) {
	switch n := node.(type) {
	case *parse.ListNode:
		if n == nil {
			return
		}
		for _, child := range n.Nodes {
			walkTemplateNodes(child, visit)
		}
	case *parse.TemplateNode:
		visit(n.Name)
	case *parse.IfNode:
		walkTemplateNodes(n.List, visit)
		if n.ElseList != nil {
			walkTemplateNodes(n.ElseList, visit)
		}
	case *parse.RangeNode:
		walkTemplateNodes(n.List, visit)
		if n.ElseList != nil {
			walkTemplateNodes(n.ElseList, visit)
		}
	case *parse.WithNode:
		walkTemplateNodes(n.List, visit)
		if n.ElseList != nil {
			walkTemplateNodes(n.ElseList, visit)
		}
	}
}
