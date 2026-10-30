# loosely based on
# http://trevorius.com/scrapbook/uncategorized/pyqt-custom-abstractitemmodel/

from PyQt6 import QtCore


class CustomNode:

    def __init__(self, model: 'CustomModel', data):
        self.model = model
        self._data = data
        self._children = []
        self._parent = None
        self._row = 0

    def get_data(self):
        return self._data

    def get_data_for_role(self, index, role):
        # define in child class
        raise NotImplementedError()

    def childCount(self):
        return len(self._children)

    def child(self, row):
        if row >= 0 and row < self.childCount():
            return self._children[row]

    def parent(self):
        return self._parent

    def row(self):
        return self._row

    def addChild(self, child):
        child._parent = self
        child._row = len(self._children)
        self._children.append(child)


class CustomModel(QtCore.QAbstractItemModel):

    def __init__(self, parent, columncount):
        QtCore.QAbstractItemModel.__init__(self, parent)
        self._root = CustomNode(self, None)
        self._columncount = columncount

    def rowCount(self, index):
        if index.isValid():
            return index.internalPointer().childCount()
        return self._root.childCount()

    def columnCount(self, index):
        return self._columncount

    def addChild(self, node, _parent):
        if not _parent or not _parent.isValid():
            parent = self._root
        else:
            parent = _parent.internalPointer()
        parent.addChild(self, node)

    def index(self, row, column, _parent=None):
        # Performance-critical function

        if not _parent or not _parent.isValid():
            parent = self._root
        else:
            parent = _parent.internalPointer()

        # Open-coded
        #   if not QtCore.QAbstractItemModel.hasIndex(self, row, column, _parent):
        # the implementation is equivalent but it's in C++,
        # so VM entries take up inordinate amounts of time (up to 25% of refresh()).
        # Sorting a big history calls this millions of times, so the
        # rowCount()/child() wrappers are open-coded too.
        children = parent._children
        if 0 <= row < len(children) and 0 <= column < self._columncount:
            return self.createIndex(row, column, children[row])
        return QtCore.QModelIndex()

    def parent(self, index):
        if index.isValid():
            node = index.internalPointer()
            if node:
                p = node.parent()
                if p:
                    return QtCore.QAbstractItemModel.createIndex(self, p.row(), 0, p)
            else:
                return QtCore.QModelIndex()
        return QtCore.QModelIndex()

    def data(self, index, role):
        if not index.isValid():
            return None
        node = index.internalPointer()
        return node.get_data_for_role(index, role)
