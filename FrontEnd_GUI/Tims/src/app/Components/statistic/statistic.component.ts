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

  dataByProviderObservable: Observable<any>;
  dataByProvider: DataByProvider[] = [];
  private chart: Chart;
  constructor(private statistic: StatisticService) { }

  ngOnInit() {
    this.getDataByProvider();
  }

  getDataByProvider() {
    this.dataByProviderObservable = this.statistic.getStatisticByProvider();
    this.dataByProviderObservable.subscribe(
      (data: DataByProvider[]) => {
        this.dataByProvider = {...data};
        this.drawChart();
        },
      error => {
        console.log('Error', error);
      }
    );
  }

  drawChart(): void {
    this.chart = new Chart({
      chart: {
        type: 'pie'
      },
      title: {
        text: 'Threats Chart By Provider'
      },
      tooltip: {
        headerFormat: '<span style="font-size:11px">{series.name}</span><br>',
        pointFormat: '<span style="color:{point.color}">{point.name}</span>: <b>{point.percentage:.2f}%</b> of total<br/>'
      },
      plotOptions: {
        series: {
          allowPointSelect: true,
          cursor: 'pointer',
          dataLabels: {
            enabled: true,
            format: '<b>{point.name}</b>: {point.percentage:.2f} %'
          }
        }
      },
      series: [
        {
          name: 'Provider',
          data:  this.getDataFromJSON()
        }
      ]
    });
  }

  getDataFromJSON() {
    const data = [];
    Object.keys(this.dataByProvider).forEach(key => data.push(this.dataByProvider[key]));
    return data;
  }

}

export interface DataByProvider {
  name: string;
  y: number;
}
