// =============================================================================
// Kernel Zxyphor - Red-Black Tree
// =============================================================================
// Self-balancing binary search tree implementation. Red-black trees provide
// O(log n) insert, delete, and lookup operations with guaranteed worst-case
// performance. Used by:
//   - CFS scheduler (tasks sorted by vruntime)
//   - VMM (virtual memory areas sorted by address)
//   - Timer wheel (sorted expiration times)
//
// Properties maintained (red-black invariants):
//   1. Every node is either red or black
//   2. The root is black
//   3. Every leaf (NIL) is black
//   4. If a node is red, both children are black
//   5. All paths from root to leaves have the same black height
// =============================================================================

// =============================================================================
// Node Colors
// =============================================================================
pub const Color = enum(u1) {
    red = 0,
    black = 1,
};

// =============================================================================
// Tree Node (intrusive — embed in your struct)
// =============================================================================
pub const RbNode = struct {
    parent: ?*RbNode = null,
    left: ?*RbNode = null,
    right: ?*RbNode = null,
    color: Color = .red,

    /// Get the grandparent
    fn grandparent(self: *RbNode) ?*RbNode {
        if (self.parent) |p| return p.parent;
        return null;
    }

    /// Get the uncle
    fn uncle(self: *RbNode) ?*RbNode {
        const gp = self.grandparent() orelse return null;
        if (self.parent == gp.left) return gp.right;
        return gp.left;
    }

    /// Get the sibling
    pub fn sibling(self: *RbNode) ?*RbNode {
        const p = self.parent orelse return null;
        if (self == p.left) return p.right;
        return p.left;
    }

    /// Check if this is a left child
    pub fn isLeftChild(self: *const RbNode) bool {
        if (self.parent) |p| return p.left == self;
        return false;
    }

    /// Check if this is a right child
    pub fn isRightChild(self: *const RbNode) bool {
        if (self.parent) |p| return p.right == self;
        return false;
    }

    /// Clear all links
    pub fn reset(self: *RbNode) void {
        self.parent = null;
        self.left = null;
        self.right = null;
        self.color = .red;
    }
};

// =============================================================================
// Red-Black Tree
// =============================================================================
pub const RbTree = struct {
    root: ?*RbNode = null,
    node_count: usize = 0,

    /// Compare function type (returns <0, 0, >0)
    pub const CompareKey = *const fn (node: *const RbNode, key: u64) i32;
    pub const CompareNodes = *const fn (a: *const RbNode, b: *const RbNode) i32;

    pub fn init() RbTree {
        return RbTree{};
    }

    /// Number of nodes in the tree
    pub fn count(self: *const RbTree) usize {
        return self.node_count;
    }

    pub fn isEmpty(self: *const RbTree) bool {
        return self.root == null;
    }

    // =========================================================================
    // Insertion
    // =========================================================================

    /// Insert a node using a comparison function
    pub fn insert(self: *RbTree, node: *RbNode, cmp: CompareNodes) void {
        node.left = null;
        node.right = null;
        node.color = .red;

        // Standard BST insert
        if (self.root == null) {
            node.parent = null;
            self.root = node;
        } else {
            var current = self.root;
            while (current) |c| {
                const result = cmp(node, c);
                if (result < 0) {
                    if (c.left == null) {
                        c.left = node;
                        node.parent = c;
                        break;
                    }
                    current = c.left;
                } else {
                    if (c.right == null) {
                        c.right = node;
                        node.parent = c;
                        break;
                    }
                    current = c.right;
                }
            }
        }

        self.node_count += 1;

        // Fix red-black violations
        self.insertFixup(node);
    }

    fn insertFixup(self: *RbTree, node_arg: *RbNode) void {
        var node = node_arg;

        while (node.parent != null and nodeColor(node.parent) == .red) {
            var parent = node.parent.?;
            var gp = parent.parent orelse break;

            if (parent == gp.left) {
                var uncle_node = gp.right;
                if (nodeColor(uncle_node) == .red) {
                    // Case 1: Uncle is red — recolor
                    parent.color = .black;
                    if (uncle_node) |u| u.color = .black;
                    gp.color = .red;
                    node = gp;
                } else {
                    if (node == parent.right) {
                        // Case 2: Node is right child — rotate left
                        node = parent;
                        self.rotateLeft(node);
                        parent = node.parent.?;
                        gp = parent.parent orelse break;
                    }
                    // Case 3: Node is left child — rotate right
                    parent.color = .black;
                    gp.color = .red;
                    self.rotateRight(gp);
                }
            } else {
                // Mirror: parent is right child of grandparent
                var uncle_node = gp.left;
                if (nodeColor(uncle_node) == .red) {
                    parent.color = .black;
                    if (uncle_node) |u| u.color = .black;
                    gp.color = .red;
                    node = gp;
                } else {
                    if (node == parent.left) {
                        node = parent;
                        self.rotateRight(node);
                        parent = node.parent.?;
                        gp = parent.parent orelse break;
                    }
                    parent.color = .black;
                    gp.color = .red;
                    self.rotateLeft(gp);
                }
            }
        }

        self.root.?.color = .black;
    }

    // =========================================================================
    // Deletion
    // =========================================================================

    /// Remove a node from the tree
    pub fn remove(self: *RbTree, node: *RbNode) void {
        var y = node;
        var y_original_color = y.color;
        var x: ?*RbNode = null;
        var x_parent: ?*RbNode = null;

        if (node.left == null) {
            x = node.right;
            x_parent = node.parent;
            self.transplant(node, node.right);
        } else if (node.right == null) {
            x = node.left;
            x_parent = node.parent;
            self.transplant(node, node.left);
        } else {
            // Node with two children: find successor
            y = minimum(node.right.?);
            y_original_color = y.color;
            x = y.right;

            if (y.parent == node) {
                x_parent = y;
                if (x) |xn| xn.parent = y;
            } else {
                x_parent = y.parent;
                self.transplant(y, y.right);
                y.right = node.right;
                if (y.right) |yr| yr.parent = y;
            }

            self.transplant(node, y);
            y.left = node.left;
            if (y.left) |yl| yl.parent = y;
            y.color = node.color;
        }

        self.node_count -= 1;

        if (y_original_color == .black) {
            self.deleteFixup(x, x_parent);
        }

        node.reset();
    }

    fn deleteFixup(self: *RbTree, x_arg: ?*RbNode, x_parent_arg: ?*RbNode) void {
        var x = x_arg;
        var x_parent = x_parent_arg;

        while (x != self.root and nodeColor(x) == .black) {
            const parent = x_parent orelse break;

            if (x == parent.left) {
                var w = parent.right orelse break;

                if (w.color == .red) {
                    w.color = .black;
                    parent.color = .red;
                    self.rotateLeft(parent);
                    w = parent.right orelse break;
                }

                if (nodeColor(w.left) == .black and nodeColor(w.right) == .black) {
                    w.color = .red;
                    x = parent;
                    x_parent = parent.parent;
                } else {
                    if (nodeColor(w.right) == .black) {
                        if (w.left) |wl| wl.color = .black;
                        w.color = .red;
                        self.rotateRight(w);
                        w = parent.right orelse break;
                    }
                    w.color = parent.color;
                    parent.color = .black;
                    if (w.right) |wr| wr.color = .black;
                    self.rotateLeft(parent);
                    x = self.root;
                    x_parent = null;
                }
            } else {
                var w = parent.left orelse break;

                if (w.color == .red) {
                    w.color = .black;
                    parent.color = .red;
                    self.rotateRight(parent);
                    w = parent.left orelse break;
                }

                if (nodeColor(w.right) == .black and nodeColor(w.left) == .black) {
                    w.color = .red;
                    x = parent;
                    x_parent = parent.parent;
                } else {
                    if (nodeColor(w.left) == .black) {
                        if (w.right) |wr| wr.color = .black;
                        w.color = .red;
                        self.rotateLeft(w);
                        w = parent.left orelse break;
                    }
                    w.color = parent.color;
                    parent.color = .black;
                    if (w.left) |wl| wl.color = .black;
                    self.rotateRight(parent);
                    x = self.root;
                    x_parent = null;
                }
            }
        }

        if (x) |xn| xn.color = .black;
    }

    // =========================================================================
    // Search
    // =========================================================================

    /// Find a node by key
    pub fn find(self: *const RbTree, key: u64, cmp: CompareKey) ?*RbNode {
        var current = self.root;
        while (current) |c| {
            const result = cmp(c, key);
            if (result == 0) return c;
            current = if (result > 0) c.left else c.right;
        }
        return null;
    }

    /// Get the minimum (leftmost) node
    pub fn getMinimum(self: *const RbTree) ?*RbNode {
        var node = self.root orelse return null;
        return minimum(node);
    }

    /// Get the maximum (rightmost) node
    pub fn getMaximum(self: *const RbTree) ?*RbNode {
        var node = self.root orelse return null;
        return maximum(node);
    }

    // =========================================================================
    // In-order traversal iterator
    // =========================================================================
    pub const Iterator = struct {
        current: ?*RbNode,

        pub fn next(self: *Iterator) ?*RbNode {
            const node = self.current orelse return null;
            self.current = successor(node);
            return node;
        }
    };

    pub fn iterator(self: *const RbTree) Iterator {
        return Iterator{ .current = self.getMinimum() };
    }

    // =========================================================================
    // Rotations
    // =========================================================================
    fn rotateLeft(self: *RbTree, x: *RbNode) void {
        const y = x.right orelse return;
        x.right = y.left;
        if (y.left) |yl| yl.parent = x;

        y.parent = x.parent;
        if (x.parent == null) {
            self.root = y;
        } else if (x == x.parent.?.left) {
            x.parent.?.left = y;
        } else {
            x.parent.?.right = y;
        }

        y.left = x;
        x.parent = y;
    }

    fn rotateRight(self: *RbTree, x: *RbNode) void {
        const y = x.left orelse return;
        x.left = y.right;
        if (y.right) |yr| yr.parent = x;

        y.parent = x.parent;
        if (x.parent == null) {
            self.root = y;
        } else if (x == x.parent.?.right) {
            x.parent.?.right = y;
        } else {
            x.parent.?.left = y;
        }

        y.right = x;
        x.parent = y;
    }

    fn transplant(self: *RbTree, u: *RbNode, v: ?*RbNode) void {
        if (u.parent == null) {
            self.root = v;
        } else if (u == u.parent.?.left) {
            u.parent.?.left = v;
        } else {
            u.parent.?.right = v;
        }
        if (v) |vn| vn.parent = u.parent;
    }
};

// =============================================================================
// Utility functions
// =============================================================================
fn nodeColor(node: ?*RbNode) Color {
    if (node) |n| return n.color;
    return .black; // NIL nodes are black
}

fn minimum(node_arg: *RbNode) *RbNode {
    var node = node_arg;
    while (node.left) |left| {
        node = left;
    }
    return node;
}

fn maximum(node_arg: *RbNode) *RbNode {
    var node = node_arg;
    while (node.right) |right| {
        node = right;
    }
    return node;
}

/// In-order successor
pub fn successor(node: *RbNode) ?*RbNode {
    if (node.right) |right| return minimum(right);

    var current = node;
    while (current.parent) |parent| {
        if (current == parent.left) return parent;
        current = parent;
    }
    return null;
}

/// In-order predecessor
pub fn predecessor(node: *RbNode) ?*RbNode {
    if (node.left) |left| return maximum(left);

    var current = node;
    while (current.parent) |parent| {
        if (current == parent.right) return parent;
        current = parent;
    }
    return null;
}

/// Get containing structure from an RbNode pointer
pub fn nodeToParent(comptime T: type, comptime field_name: []const u8, node: *RbNode) *T {
    const offset = @offsetOf(T, field_name);
    const node_addr = @intFromPtr(node);
    return @ptrFromInt(node_addr - offset);
}
