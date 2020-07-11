package arrayutil

// IntersectionStr finds common strings in two of array
func IntersectionStr(a, b []string) (c []string) {
	m := make(map[string]bool)
	c = []string{}
	for _, item := range a {
		m[item] = true
	}

	for _, item := range b {
		if _, ok := m[item]; ok {
			c = append(c, item)
		}
	}
	return
}
