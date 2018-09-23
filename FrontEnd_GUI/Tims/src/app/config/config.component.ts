import { Component, OnInit } from '@angular/core';

@Component({
  selector: 'app-config',
  templateUrl: './config.component.html',
  styleUrls: ['./config.component.css']
})
export class ConfigComponent implements OnInit {

  config: Config = {
    feedSources: ['Source A', 'Source B'],
    time: 12,
    exportFormat: ['CVS', 'JSON', 'Bro']
  };

  constructor() { }

  ngOnInit() {
  }

  readfile() {

  }
}

interface Config {
  feedSources: Array<string>;
  time: number;
  exportFormat: Array<string>;
}
