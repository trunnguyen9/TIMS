import { Component, OnInit } from '@angular/core';
import {Observable} from 'rxjs';
import {Chart} from 'angular-highcharts';
import {StatisticService} from '../../Services/statistic.service';
import {Router} from '@angular/router';

@Component({
  selector: 'app-provider-chart',
  templateUrl: './provider-chart.component.html',
  styleUrls: ['./provider-chart.component.css']
})
export class ProviderChartComponent implements OnInit {

  dataByProviderObservable: Observable<any>;
  dataByProvider: DataByProvider[] = [];
  chart: Chart;
  constructor(private statistic: StatisticService, private router: Router) { }

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
        if (error.status = 403) {
          this.router.navigate(['/login']);
        }
      }
    );
  }

  drawChart(): void {
    this.chart = new Chart({
      chart: {
        type: 'pie'
      },
      title: {
        text: 'Provider Chart'
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
