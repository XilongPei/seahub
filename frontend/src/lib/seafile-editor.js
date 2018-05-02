import React from 'react';
import '../css/seafile-editor.css';

import RichMarkdownEditor from './rich-markdown-editor';
import PlainMarkdownEditor from './plain-markdown-editor';


class SeafileEditor extends React.Component {

  state = {
    initialMarkdownContent: "",
    markdownContent: "",
    isTreeDataLoaded: false,
    editor: "rich"
  }

  setContent(markdownContent) {
    this.setState({
      initialMarkdownContent: markdownContent,
      markdownContent: markdownContent
    })
  }

  componentDidMount() {
    this.setContent(this.props.markdownContent);
  }

  componentWillReceiveProps(nextProps) {
    this.setContent(nextProps.markdownContent);
  }

  switchToPlainTextEditor = (content) => {
    this.setState({
      editor: "plain",
      markdownContent: content
    });
  }

  switchToRichTextEditor = (content) => {
    this.setState({
      editor: "rich",
      markdownContent: content
    });
  }

  render() {
    if (this.state.editor === "rich") {
      return (
        <RichMarkdownEditor
          markdownContent={this.state.markdownContent}
          onSave={this.props.onSave}
          treeData={this.props.treeData}
          editorUtilities={this.props.editorUtilities}
          switchToPlainTextEditor={this.switchToPlainTextEditor}
          onChange={this.onChange}
        />
      );
    } else {
      return (
        <PlainMarkdownEditor
          markdownContent={this.state.markdownContent}
          switchToRichTextEditor={this.switchToRichTextEditor}
          editorUtilities={this.props.editorUtilities}
        />
      );
    }
  }

}

export default SeafileEditor;
