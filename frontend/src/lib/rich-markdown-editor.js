import React from 'react';
import { Editor, getEventTransfer, getEventRange } from 'slate-react';
import EditCode from 'slate-edit-code'
import EditTable from 'slate-edit-table'
import EditList from 'slate-edit-list'
import EditBlockquote from 'slate-edit-blockquote'
import InsertImages from 'slate-drop-or-paste-images'
import SidePanel from './side-panel';
import { Image } from './image';
import { Value, Inline, Text } from 'slate';
import AddImageDialog from './add-image-dialog';
import AddLinkDialog from './add-link-dialog';
import SeafileSlatePlugin from './seafile-slate-plugin';
import { serialize, deserialize } from '../slate2markdown';
import Alert from 'react-s-alert';
import 'react-s-alert/dist/s-alert-default.css';
import 'react-s-alert/dist/s-alert-css-effects/scale.css';
import isUrl from 'is-url'
import { IconButton, TableToolBar, Button, ButtonGroup, MoreMenu } from "./topbarcomponent/editorToolBar";
var lodash = require('lodash');
var deepEqual = require('deep-equal');


const DEFAULT_NODE = 'paragraph';
const editCode = EditCode();
const editTable = EditTable();
const editBlockquote = EditBlockquote();
const editList = EditList({
  types: ["ordered_list", "unordered_list"]
});

/*
  When an image is pasted or dropped, insertImage() will be called.
  insertImage creates an image node with `file` stored in `data`.
*/
const insertImages = InsertImages({
  extensions: ['png'],
  insertImage: (change, file, editor) => {
    var node = Inline.create({
      type: 'image',
      isVoid: true,
      data: {
        file: file
      }
    })
    // schedule image uploading
    editor.props.editorUtilities.uploadImage(file).then((imageURL) => {
      // change the node property after image uploaded
      const change2 = editor.props.value.change();
      change2.setNodeByKey(node.key, {
        data: {
          src: imageURL
        }
      });
      editor.props.onChange(change2);
    })
    return change.insertInline(node);
  }
});

var seafileSlatePlugin = new SeafileSlatePlugin({
  editCode,
});

const plugins = [
  editTable,
  editList,
  editCode,
  insertImages,
  editBlockquote,
  seafileSlatePlugin
]


class RichMarkdownEditor extends React.Component {

  state = {
    showAddImageDialog: false,
    isSelectedImage:false,
    leftNavMode: "files",
    initialMarkdownContent: "",
    savedContent: "",
    value: deserialize(""),
    saving: false,
    contentChanged: false,
    showAddLinkDialog: false,
    rightWidth: 75,
    resizeFlag: false
  };

  constructor(props) {
    super(props);
    this.checkNeedSave = lodash.throttle(this._checkNeedSave, 1000);
    seafileSlatePlugin.editor = this;
  }

  _checkNeedSave(newValue) {
    const v = serialize(newValue.toJSON());

    if (v == this.state.savedContent) {
      this.setState({
        contentChanged: false,
      })
    } else {
      this.setState({
        contentChanged: true,
      })
    }
  }

  setContent(markdownContent) {
    const value = deserialize(markdownContent);
    this.setState({
      value: value,
      isSelectedImage: false,
      initialMarkdownContent: markdownContent,
      contentChanged: false,
      savedContent: serialize(value.toJSON())
    })
    window.setTimeout(() => {
      const change = this.state.value.change();
      change.focus();
      this.onChange(change);
    }, 250);
  }

  componentDidMount() {
    this.setContent(this.props.markdownContent);
  }

  componentWillReceiveProps(nextProps) {
    this.setContent(nextProps.markdownContent);
  }

  scrollToNode = (node) => {
    // TODO: scroll to the corresponding position, make the focus on
    // the center of the screen
    const change = this.state.value.change().collapseToStartOf(node).focus();
    this.onChange(change);
  }

  /**
  * Check if the current selection has a mark with `type` in it.
  *
  * @param {String} type
  * @return {Boolean}
  */
  hasMark = type => {
    const value = this.state.value
    return value.activeMarks.some(mark => mark.type === type)
  }

  /*
     check if selected are 'link'
  */
  hasLinks = value => {
    return value.inlines.some(inline => inline.type === 'link')
  }

  isInTable() {
    return editTable.utils.isSelectionInTable(this.state.value);
  }

  isInCode() {
    return editCode.utils.isInCodeBlock(this.state.value);
  }

  /*
    check if wrap link
  */
  onToggleLink = event => {
    event.preventDefault();
    const { value } = this.state;
    const hasLinks = this.hasLinks(value);
    const change = value.change();
    if (hasLinks) {
      change.call((change) => {
        change.unwrapInline('link');
      });
      this.onChange(change);

    } else {
      this.toggleLinkDialog();
    }
  }

  /*
    set link href
  */
  onSetLink = url => {
    const { value } = this.state;
    const change = value.change();
    if (value.isExpanded) {
      change.call((change, href) => {
        change.wrapInline({
          type: 'link',
          data: { href }
        });
        change.collapseToEnd();
      }, url);
    } else {
      const inlineText = Inline.create({
        data: { href: url },
        type: 'link',
        nodes: [Text.create({text:url})]
      });
      change.insertInline(inlineText);
      change.collapseToEnd();
    }
    this.onChange(change);
  }

  toggleLinkDialog = () => {
    this.setState({
      showAddLinkDialog: !this.state.showAddLinkDialog
    });
  }

  /**
   * Check if the any of the currently selected blocks are of `type`.
   *
   * @param {String} type
   * @return {Boolean}
   */

  hasBlock = type => {
    const value = this.state.value
    return value.blocks.some( node => node.type === type)
  }

  onChange = (change) => {
    this.setState({ value: change.value });

    const ops = change.operations
      .filter(o => o.type != 'set_selection' && o.type != 'set_value')
    if (ops.size != 0) {
      this.checkNeedSave(change.value);
    }
  }

  /**
  * When a mark button is clicked, toggle the current mark.
  *
  * @param {Event} event
  * @param {String} type
  */

  onClickMark = (event, type) => {
    event.preventDefault()
    const value = this.state.value;
    const change = value.change().toggleMark(type)
    this.onChange(change)
  }

  /**
   * When a block button is clicked, toggle the block type.
   *
   * @param {Event} event
   * @param {String} type
   */
  onClickBlock = (event, type) => {
    event.preventDefault()
    const value = this.state.value;
    const change = value.change()
    const { document } = value
    // Handle everything but list buttons.
    if (type === 'block-quote') {
      const isInBlockquote = editBlockquote.utils.isSelectionInBlockquote(value);
      if (isInBlockquote) {
        editBlockquote.changes.unwrapBlockquote(change);
      } else {
        editBlockquote.changes.wrapInBlockquote(change);
      }
    } else if (type === 'ordered_list' || type === 'unordered_list') {
      const isType = value.blocks.some(block => {
        return !!document.getClosest(block.key, parent => parent.type === type)
      });
      if (isType) {
        editList.changes.unwrapList(change);
      } else {
        editList.changes.wrapInList(editList.changes.unwrapList(change), type);
      }

    } else {
      const isActive = this.hasBlock(type);
      change.setBlocks(isActive ? DEFAULT_NODE : type)
    }
    this.onChange(change);
  }

  /**
   * Toggle inline code or code block
   *
   * @param {Event} event
   */
  onToggleCode = (event) => {
    event.preventDefault()
    const value = this.state.value
    const { selection } = value
    const change = value.change()
    this.onChange(editCode.changes.toggleCodeBlock(change))
  }

  /**
   * Add table
   *
   * @param {Event} event
   */
  onAddTable(event) {
    event.preventDefault()
    const value = this.state.value
    const { selection } = value
    const change = value.change()
    if (editTable.utils.isSelectionInTable(value)) {
      editTable.changes.removeTable(change)
    } else {
      editTable.changes.insertTable(change, 2, 2)
      // need to set table align, otherwise markup-it will throw error
      editTable.changes.setColumnAlign(change, "left", 0)
      editTable.changes.setColumnAlign(change, "left", 1)
    }
    this.onChange(change)
  }

  onInsertImage = (url) => {
    const change = this.state.value.change().insertInline({
      type: 'image',
      isVoid: true,
      data: { src: url },
    });
    this.onChange(change);
  }

  toggleImageDialog = () => {
    this.setState({
      showAddImageDialog: !this.state.showAddImageDialog
    });
  }

  /**
   * Add image
   *
   * @param {Event} event
   */
  onAddImage = (event) => {
    event.preventDefault()

    this.toggleImageDialog();

    /*
    const src = window.prompt('Enter the URL of the image:')
    if (!src) return

    const { value } = this.state
    const change = value.change().call(insertImage, src)

    this.onChange(change)
    */
  }

  /**
   * Save content
   *
   * @param {Event} event
   */
  onSave = (event) => {
    const { value } = this.state;
    const str = serialize(value.toJSON());
    var promise = this.props.editorUtilities.saveContent(str).then(() => {
      this.setState({
        saving: false,
        contentChanged: false,
        savedContent: str
      });
      Alert.success('File saved.', {
            position: 'bottom-right',
            effect: 'scale',
            timeout: 1000
      });
    }, () => {
      this.setState({
        saving: false
      });
      Alert.error('File failed to save.', {
            position: 'bottom-right',
            effect: 'scale',
            timeout: 1000
      });
    });
    this.setState({
      saving: true
    })
  }
     
  /**
   * Render a Slate node.
   *
   * @param {Object} props
   * @return {Element}
   */

  renderNode = props => {
    /*
       props contains  { attributes, children, node, isSelected, editor, parent, key }
    */
    const { attributes, children, node, isSelected } = props
    let textAlign;
    switch (node.type) {
      case 'paragraph':
        return <p {...attributes}>{children}</p>
      case 'blockquote':
        return <blockquote {...attributes}>{children}</blockquote>
      case 'header_one':
        return <h1 {...attributes}>{children}</h1>
      case 'header_two':
        return <h2 {...attributes}>{children}</h2>
      case 'header_three':
        return <h3 {...attributes}>{children}</h3>
      case 'header_four':
        return <h4 {...attributes}>{children}</h4>
      case 'header_five':
        return <h5 {...attributes}>{children}</h5>
      case 'header_six':
        return <h6 {...attributes}>{children}</h6>
      case 'list_item':
        return <li {...attributes}>{children}</li>
      case 'unordered_list':
        return <ul {...attributes}>{children}</ul>
      case 'ordered_list':
        return <ol {...attributes}>{children}</ol>
      case 'image':
        return <Image {...props}/>
      case 'code_block':
        return (
          <pre className="code" {...attributes}>
          {children}
          </pre>
        );
      case 'code_line':
        return <p>{children}</p>;
      case 'table':
        return (
          <table>
            <tbody {...attributes}>{children}</tbody>
          </table>
        );
      case 'table_row':
        return <tr {...attributes}>{children}</tr>;
      case 'table_cell':
        textAlign = node.get('data').get('textAlign');
        textAlign = ['left', 'right', 'center'].indexOf(textAlign) === -1
            ? 'left' : textAlign;
        return (
          <td style={{ textAlign }} {...attributes}>
          {children}
          </td>
        );
      case 'link':
        var href = node.get('data').get('href');
        return (
          <a href={ href }>{children}</a>
        );
      case 'hr':
        var className = isSelected ? 'active' : null
        return (
          <hr className={className} />
        );
    }
  }

  renderMark = props => {
    const { children, mark, node } = props
    switch (mark.type) {
      case 'BOLD':
      return <strong>{children}</strong>
      case 'CODE':
      return <code>{children}</code>
      case 'ITALIC':
      return <em>{children}</em>
    }
  }

  hasSelectImage (value) {
    /*
    * get image obj when selected,has not found a better way
    * */
    let imageObj = value.inlines.toJSON()[0];
    if (imageObj && imageObj.type === 'image') {
      return true
    }
    return false
  }

  switchToPlainTextEditor = () => {
    const { value } = this.state;
    const str = serialize(value.toJSON());
    this.props.switchToPlainTextEditor(str);
  }

  /**** resize ****/
  onResizeMouseUp = (event) => {
    this.setState({
      resizeFlag: false
    });
  }

  onResizeMouseDown = (event) => {
    this.setState({
      resizeFlag: true
    })
  }

  onResizeMouseMove = (event) => {
    const rightWidth = this.state.rightWidth - (event.nativeEvent.movementX / event.view.innerWidth)*100;
    this.setState({
      rightWidth: rightWidth,
    });
  }

  render() {
    const value = this.state.value;
    const onResizeMove = this.state.resizeFlag ? this.onResizeMouseMove : null;
    return (
      <div className='seafile-editor'>
        <div className="seafile-editor-topbar">
          <div className="title"><img src={ require('../assets/seafile-logo.png') } alt=""/></div>
            {this.renderToolbar()}
        </div>
        <div className="seafile-editor-main d-flex" onMouseMove={onResizeMove} onMouseUp={this.onResizeMouseUp}>
            <div className="seafile-editor-left-panel align-self-start" style={{flexBasis:(100-this.state.rightWidth)+'%'}}>
              <SidePanel
                editor={this}
                value={this.state.value}
                editorUtilities={this.props.editorUtilities}
              />
            </div>
            <div className="seafile-editor-right-panel align-self-end" style={{flexBasis:this.state.rightWidth+'%'}}>
              <div className="seafile-editor-resize" onMouseDown={this.onResizeMouseDown}></div>
              <div className="editor-container">
              <div className="editor article">
                <Editor
                    value={this.state.value}
                    autoFocus={true}
                    plugins={plugins}
                    onChange={this.onChange}
                    onKeyDown={this.onKeyDown}
                    renderNode={this.renderNode}
                    renderMark={this.renderMark}
                    onDrop={this.onDrop}
                    editorUtilities={this.props.editorUtilities}
                />
              </div>
              </div>
          </div>
        </div>
      </div>
    )
  }

  renderToolbar = () => {
    const value = this.state.value;
    var isTableActive = false;
    var isCodeActive = false;
    try {
      isTableActive = editTable.utils.isSelectionInTable(value);
      isCodeActive = editCode.utils.isInCodeBlock(value);
    } catch (err) {
      console.log(err);
    }
    const isImageActive = this.hasSelectImage(value);
    const isLinkActive = this.hasLinks(value);

    let showMarkButton = true, showBlockButton = true, showCodeButton = true,
      showImageButton = true, showAddTableButton = true, showLinkButton = true;
    let isSaveActive = this.state.contentChanged;

    if (isCodeActive) {
      showMarkButton = false;
      showBlockButton = false;
      showCodeButton = true;
      showImageButton = false;
      showAddTableButton = false;
      showLinkButton = false;
    }
    if (isTableActive) {
      showMarkButton = true;
      showCodeButton = false;
      showImageButton = true;
      showBlockButton = false ;
      showAddTableButton = false;
      showLinkButton = true;
    }
    return (
      <div className="menu toolbar-menu">
        {
          showMarkButton === true &&
          <ButtonGroup>
            {this.renderMarkButton("BOLD", "fa fa-bold")}
            {this.renderMarkButton('ITALIC', 'fa fa-italic')}
          </ButtonGroup>
        }
        { showBlockButton === true &&
          <ButtonGroup>
            {this.renderBlockButton('header_one', 'fa fa-h1')}
            {this.renderBlockButton('header_two', 'fa fa-h2')}
          </ButtonGroup>
        }
        { showBlockButton === true &&
          <ButtonGroup>
            {this.renderBlockButton('block-quote', 'fa fa-quote-left')}
            {this.renderBlockButton('ordered_list', 'fa fa-list-ol')}
            {this.renderBlockButton('unordered_list', 'fa fa-list-ul')}
          </ButtonGroup>
        }

        <ButtonGroup>
          {
            showLinkButton === true &&
            <IconButton icon={'fa fa-link'} isActive={isLinkActive} onMouseDown={this.onToggleLink}/>
          }
          { showCodeButton === true &&
            <IconButton icon={"fa fa-code"} onMouseDown={this.onToggleCode} isActive={isCodeActive}/>
          }
          { showAddTableButton === true && this.renderAddTableButton()}
          { showImageButton === true &&
            <IconButton icon={"fa fa-image"} onMouseDown={this.onAddImage} isActive={isImageActive}/>
          }
        </ButtonGroup>
        { isTableActive === true && this.renderTableToolbar()}
        { this.state.saving ? (
          <ButtonGroup>
            <button type={"button"} className={"btn btn-icon btn-secondary btn-active btn-loading"} >
              <i className={"fa fa-save"}/>
            </button>
          </ButtonGroup>
        ) : (
          <ButtonGroup>
            <IconButton icon={"fa fa-save"} onMouseDown={this.onSave} disabled={!isSaveActive} isActive={isSaveActive}/>
          </ButtonGroup>
        )}
        <MoreMenu switchToPlainTextEditor={this.switchToPlainTextEditor} />
        <AddImageDialog
          showAddImageDialog={this.state.showAddImageDialog}
          toggleImageDialog={this.toggleImageDialog}
          onInsertImage={this.onInsertImage}
        />
        <AddLinkDialog
          showAddLinkDialog={this.state.showAddLinkDialog}
          toggleLinkDialog={this.toggleLinkDialog}
          onSetLink={this.onSetLink}
        />
        <Alert stack={{limit: 3}} />
      </div>
    )
  }

  renderAddTableButton = () => {
    const onAddTable = event => this.onAddTable(event);
    return(
      <IconButton icon={'fa fa-table'} onMouseDown={onAddTable}/>
    )
  };

  renderTableToolbar = () => {
    return (
      <TableToolBar
        onRemoveTable={this.onRemoveTable}
        onInsertColumn={this.onInsertColumn}
        onRemoveColumn={this.onRemoveColumn}
        onInsertRow={this.onInsertRow}
        onRemoveRow={this.onRemoveRow}
        onSetAlign={this.onSetAlign}
      />
    )
  }

  onInsertColumn = event => {
    event.preventDefault();
    this.onChange(editTable.changes.insertColumn(this.state.value.change()))
  };

  onInsertRow = event => {
    event.preventDefault();
    this.onChange(editTable.changes.insertRow(this.state.value.change()));
  };

  onRemoveColumn = event => {
    event.preventDefault();
    this.onChange(editTable.changes.removeColumn(this.state.value.change()));
  };

  onRemoveRow = event => {
    event.preventDefault();
    this.onChange( editTable.changes.removeRow(this.state.value.change()));
  };

  onRemoveTable = event => {
    event.preventDefault();
    this.onChange( editTable.changes.removeTable(this.state.value.change()));
  };

  onSetAlign = (event, align) => {
    event.preventDefault();
    this.onChange(editTable.changes.setColumnAlign(this.state.value.change(),align));
  };

  renderMarkButton = (type, icon) => {
    const isActive = this.hasMark(type);
    const onMouseDown = event => this.onClickMark(event, type);
    return (
      // eslint-disable-next-line react/jsx-no-bind
      <IconButton onMouseDown={onMouseDown} isActive={isActive} icon={icon}></IconButton>
    )
  }

  /**
  * Render a block-toggling toolbar button.
  *
  * @param {String} type
  * @param {String} icon
  * @return {Element}
  */
  renderBlockButton = (type, icon) => {
    let isActive = false;
    if (type === 'ordered_list' || type === 'unordered_list')  {
      const listBlock = editList.utils.getCurrentList(this.state.value);
      isActive = listBlock && listBlock.type === type;
    } else if (type === 'block-quote') {
      isActive = editBlockquote.utils.isSelectionInBlockquote(this.state.value);
    } else {
      if (this.state.value.isFocused) {
        isActive = this.hasBlock(type);
      }
    }
    const onMouseDown = event => this.onClickBlock(event, type);
    return (
      // eslint-disable-next-line react/jsx-no-bind
      <IconButton onMouseDown={onMouseDown} isActive={isActive} icon={icon}/>
    )
  }

}

export default RichMarkdownEditor;
