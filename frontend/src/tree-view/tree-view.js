import React from 'react';
import TreeNodeView from './tree-node-view';
import Tree from './tree';

class TreeView extends React.Component {

  static defaultProps = {
    paddingLeft: 20
  };

  state = {
    tree: new Tree(),
    loadingFailed: false
  }

  componentDidMount() {
    this.props.editorUtilities.getFiles().then((files) => {
      // construct the tree object
      var rootObj = {
        name: '/',
        type: 'dir',
        isExpanded: true
      }
      var treeData = new Tree();
      treeData.parseFromList(rootObj, files);
      this.setState({
        tree: treeData
      })
    }, () => {
      console.log("failed to load files");
      this.setState({
        loadingFailed: true
      })
    })
  }


  render() {
    const tree = this.state.tree;
    if (!tree.root) {
      return <div>Loading...</div>
    }

    return (
      <div className="tree-view tree">
        <TreeNodeView
          tree={tree}
          node={tree.root}
          onDragStart={this.onDragStart}
          paddingLeft={20}
          onCollapse={this.toggleCollapse}
        />
      </div>
    );
  }

  change = (tree) => {
    /*
    this._updated = true;
    if (this.props.onChange) this.props.onChange(tree.obj);
    */
  }

  toggleCollapse = (node) => {
    const tree = this.state.tree;
    node.isExpanded = !node.isExpanded;

    this.setState({
      tree: tree
    });

    this.change(tree);
  }

  onDragStart = (e, node) => {
    const url = this.props.editorUtilities.getFileURL(node);
    e.dataTransfer.setData("text/uri-list", url);
    e.dataTransfer.setData("text/plain", url);
  }

}

export default TreeView;
