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
    for (const format of this.config.exportFormat) {
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

  ngOnInit() {
    this.configForm = this.fb.group({
      feedSources: this.fb.array([]),
      time: [''],
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
      },
      error => {
        console.log('Error', error);
      }
    );
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
