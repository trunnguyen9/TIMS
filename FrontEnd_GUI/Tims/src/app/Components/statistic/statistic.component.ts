import {Component, OnInit} from '@angular/core';
import {StatisticService} from '../../Services/statistic.service';
import {Observable} from 'rxjs';
import { Chart } from 'angular-highcharts';

@Component({
  selector: 'app-statistic',
  templateUrl: './statistic.component.html',
  styleUrls: ['./statistic.component.css']
})
export class StatisticComponent implements OnInit {

  constructor() { }

  ngOnInit() {}

}
