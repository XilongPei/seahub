import React from 'react';

function sortByType(a, b) {
  if (a.type == "dir" && b.type != "dir") {
    return -1;
  } else if (a.type != "dir" && b.type == "dir") {
    return 1;
  } else {
    return a.name.localeCompare(b.name);
  }
}

class TreeNodeView extends React.Component {

  renderCollapse = () => {
    const { node } = this.props;

    if (node.hasChildren()) {
      const { isExpanded } = node;

      return (
        <span
          className={isExpanded ? 'collapse-node caret-down' : 'collapse-node caret-right'}
          onMouseDown={e => e.stopPropagation()}
          onClick={this.handleCollapse}
        />
      );
    }

    return null;
  }

  renderChildren = () => {
    const { node, tree } = this.props;

    if (node.children && node.children.length) {
      const childrenStyles = {
        paddingLeft: this.props.paddingLeft
      };
      var l = node.children.sort(sortByType);

      /*
        the `key` property is needed. Otherwise there is a warning in the console
      */
      return (
        <div className="children" style={childrenStyles}>
          {node.children.map(child => {
            return (
              <TreeNodeView
                tree={tree}
                node={child}
                key={child.path()}
                paddingLeft={this.props.paddingLeft}
                onCollapse={this.props.onCollapse}
                onDragStart={this.props.onDragStart}
              />
            );
          })}
        </div>
      );
    }

    return null;
  }

  render() {
    const { node } = this.props;
    const styles = {};
    var icon;
    if (node.type === "dir") {
      icon = <i className="far fa-folder"></i>;
    } else  {
      let index = node.name.lastIndexOf(".");
      if (index == -1) {
        icon = <i className="far fa-file"></i>;
      } else {
        let type = node.name.substring(index).toLowerCase();
        if (type == ".png" || type == ".jpg") {
          icon = <i className="far fa-image"></i>;
        } else {
          icon = <i className="far fa-file"></i>;
        }
      }
    }

    return (
      <div
        className="tree-node"
        style={styles}
      >
        <div className="tree-node-inner text-nowrap">
          {this.renderCollapse()}
          <span className="tree-node-icon">
          {icon}
          </span>
          <span draggable="true" onDragStart={this.onDragStart}>{node.name}</span>
        </div>
        {node.isExpanded ? this.renderChildren() : null}
      </div>
    );
  }

  handleCollapse = e => {
    e.stopPropagation();
    const node = this.props.node;

    if (this.props.onCollapse) {
      this.props.onCollapse(node);
    }
  }

  onDragStart = e => {
    const { node } = this.props;
    this.props.onDragStart(e, node);
  }

}

export default TreeNodeView;
