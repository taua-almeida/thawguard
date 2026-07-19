package web

// Shared view-model helpers for the diagnostics-table pages (/activity,
// /webhooks, /publications). Only the pagination window and filter-chip
// shapes are shared; each page keeps its own query struct, URL builder,
// column markup, and badge mapping. The template side is ui/pager.

// tablePager is the "Showing From–To of Total" footer with optional
// previous/next URLs. A nil pager means everything fits on one page and the
// footer stays hidden.
type tablePager struct {
	From    int
	To      int
	Total   int
	PrevURL string
	NextURL string
}

// paginateTable computes the pager window for a 1-based page of size items.
// Callers clamp page to the last non-empty page before calling, so From/To
// describe a real slice of the results.
func paginateTable(total, page, size int, urlFor func(page int) string) *tablePager {
	if size <= 0 || total <= size {
		return nil
	}
	if page < 1 {
		page = 1
	}
	from := min((page-1)*size+1, total)
	to := min(page*size, total)
	pager := &tablePager{From: from, To: to, Total: total}
	if page > 1 {
		pager.PrevURL = urlFor(page - 1)
	}
	if to < total {
		pager.NextURL = urlFor(page + 1)
	}
	return pager
}

// filterChip is one entry in a diagnostics table's filter-chip row.
type filterChip struct {
	Label  string
	URL    string
	Active bool
}

// filterChipOption pairs a chip's query value with its visible label.
type filterChipOption struct {
	Value string
	Label string
}

// filterChips builds one chip per option, marking the option whose value
// matches current as active. urlFor builds each chip's page-1 URL.
func filterChips(current string, options []filterChipOption, urlFor func(value string) string) []filterChip {
	chips := make([]filterChip, 0, len(options))
	for _, option := range options {
		chips = append(chips, filterChip{
			Label:  option.Label,
			URL:    urlFor(option.Value),
			Active: option.Value == current,
		})
	}
	return chips
}
