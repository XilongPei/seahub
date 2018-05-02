import React from 'react'
import { Dropdown, DropdownToggle, DropdownMenu, DropdownItem } from 'reactstrap'

class DropDownBox extends React.Component {
  constructor(props) {
    super(props);
    this.state= {
      dropdownOpen:false
    }
  }

  toggle= () => {
    this.setState({
      dropdownOpen:!this.state.dropdownOpen
    });
  }

  render() {
    return (
      <Dropdown isOpen={this.state.dropdownOpen} toggle={this.toggle}>
        <DropdownToggle caret>
          Set align
        </DropdownToggle>
        <DropdownMenu className={'drop-list'}>
          <DropdownItem onMouseDown={e => this.props.onSetAlign(e, 'left')}>Left</DropdownItem>
          <DropdownItem onMouseDown={e => this.props.onSetAlign(e, 'center')}>Center</DropdownItem>
          <DropdownItem onMouseDown={e => this.props.onSetAlign(e, 'right')}>Right</DropdownItem>
        </DropdownMenu>
      </Dropdown>
    )
  }
}

class MoreMenu extends React.Component {
  constructor(props) {
    super(props);
    this.state= {
      dropdownOpen:false
    }
  }

  toggle= () => {
    this.setState({
      dropdownOpen:!this.state.dropdownOpen
    });
  }

  render() {
    return (
      <Dropdown isOpen={this.state.dropdownOpen} toggle={this.toggle}>
        <DropdownToggle>
          <i className="fa fa-ellipsis-v"></i>
        </DropdownToggle>
        <DropdownMenu className={'drop-list'}>
          <DropdownItem onMouseDown={this.props.switchToPlainTextEditor}>Switch to Plain Text Editor</DropdownItem>
        </DropdownMenu>
      </Dropdown>
    )
  }
}

class ButtonGroup extends React.Component {
  render() {
    return (
      <div className={"btn-group"} role={"group"}>
        {this.props.children}
      </div>
    )
  }
}

class Button extends React.Component {
  render() {
    return (
      <button type={"button"} onMouseDown={this.props.onMouseDown}
        className={"btn btn-secondary btn-active"}>
        { this.props.children }
      </button>
    )
  }
}

class IconButton extends React.Component {
  render() {
    return (
      <button type={"button"} onMouseDown={this.props.onMouseDown}
        className={"btn btn-icon btn-secondary btn-active"}
        data-active={ this.props.isActive || false }
        disabled={this.props.disabled}>
          <i className={this.props.icon}></i>
      </button>
    )
  }
}


class TableToolBar extends React.Component {
  render() {
    return (
      <div className={'tableToolBar'}>
        <ButtonGroup>
        <Button onMouseDown={this.props.onRemoveTable}>{'Remove table'}</Button>
        </ButtonGroup>
        <ButtonGroup>
          <Button onMouseDown={this.props.onInsertColumn}>+</Button>
          <Button>{'Column'}</Button>
          <Button onMouseDown={this.props.onRemoveColumn}>-</Button>
        </ButtonGroup>
        <ButtonGroup>
          <Button onMouseDown={this.props.onInsertRow}>+</Button>
          <Button>{'Row'}</Button>
          <Button onMouseDown={this.props.onRemoveRow}>-</Button>
        </ButtonGroup>
        <DropDownBox onSetAlign={this.props.onSetAlign}/>
      </div>
    )
  }
}

export { IconButton, TableToolBar, Button, ButtonGroup, MoreMenu }
