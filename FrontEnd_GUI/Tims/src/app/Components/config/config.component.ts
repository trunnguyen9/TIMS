import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, FormArray } from '@angular/forms';
import {ConfigService} from '../../Services/config.service';
import {Observable} from 'rxjs';

@Component({
  selector: 'app-config',
  templateUrl: './config.component.html',
  styleUrls: ['./config.component.css']
})
export class ConfigComponent implements OnInit {

  config: Config ;
  timeList = [
    {'name': '2 hours', 'value': 2},
    {'name': '4 hours', 'value': 4},
    {'name': '6 hours', 'value': 6},
    {'name': '12 hours', 'value': 12},
    {'name': '24 hours', 'value': 24}
  ];
  configForm: FormGroup;
  configObservable: Observable<Config>;

  constructor(private fb: FormBuilder, private configService: ConfigService) {
  }

  addFeedSourcesForm() {
    const control = <FormArray>this.configForm.controls.feedSources;
    for (const source of this.config.feedSources) {
      control.push(
        this.fb.group({
          name: ['']
        })
      );
    }
  }

  addExportFormatForm() {
    const control = <FormArray>this.configForm.controls.exportFormat;
    for (const type of this.config.exportFormat) {
      control.push(
        this.fb.group({
          name: ['']
        })
      );
    }
  }

  addTimeForm() {
    const control = <FormArray>this.configForm.controls.time;
    for (const time of this.timeList) {
      control.push(
        this.fb.group({
          name: ['']
        })
      );
    }
  }

  getFeedSourcesFormData() {
    return <FormArray>this.configForm.get('feedSources');
  }
  getExportFormatFormData() {
    return <FormArray>this.configForm.get('exportFormat');
  }
  getTimeFormData() {
    return <FormArray>this.configForm.get('time');
  }
  ngOnInit() {
    this.configForm = this.fb.group({
      feedSources: this.fb.array([]),
      time: this.fb.array([]),
      exportFormat: this.fb.array([])
    });
    this.getConfig();
  }

  getConfig() {
    this.configObservable = this.configService.getConfig();
    this.configObservable.subscribe(
      (data: Config) => {
        this.config = { ...data };
        this.addFeedSourcesForm();
        this.addExportFormatForm();
        this.addTimeForm();
      },
      error => {
        console.log('Error', error);
      }
    );
  }
  changeTime(selectedValue: number) {
    this.config.time = selectedValue;
  }

  saveConfig() {
    this.configService.updateConfig(this.config).subscribe(
      (data) => {
        console.log('Success', data);
      },
      error => {
        console.log('Error', error);
      }
    );
  }
}

export interface Config {
  feedSources: { name: string, selected: boolean }[];
  time: number;
  exportFormat: { name: string, selected: boolean }[];
}
