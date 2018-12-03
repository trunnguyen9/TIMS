import { Component, OnInit } from '@angular/core';
import {Observable} from 'rxjs';
import {Chart} from 'angular-highcharts';
import {StatisticService} from '../../Services/statistic.service';
import {Router} from '@angular/router';

@Component({
  selector: 'app-threat-chart',
  templateUrl: './threat-chart.component.html',
  styleUrls: ['./threat-chart.component.css']
})
export class ThreatChartComponent implements OnInit {

  dataByThreatObservable: Observable<any>;
  dataByThreat;
  chart: Chart;
  constructor(private statistic: StatisticService, private router: Router) { }

  ngOnInit() {
    this.getDataByThreat();
  }

  getDataByThreat() {
    this.dataByThreatObservable = this.statistic.getStatisticByThreat();
    this.dataByThreatObservable.subscribe(
      (data) => {
        this.dataByThreat = data;
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
        type: 'column'
      },
      title: {
        text: 'Threat Chart'
      },
      xAxis: {
        type: 'category',
        labels: {
          rotation: -45,
          style: {
            fontSize: '13px',
            fontFamily: 'Verdana, sans-serif'
          }
        }
      },
      yAxis: {
        min: 0,
        title: {
          text: 'Number of Threats'
        }
      },
      legend: {
        enabled: false
      },
      tooltip: {
        pointFormat: 'Number of Threat: <b>{point.y:.1f} threats</b>'
      },
      series: [
        {
          name: 'Number of Threat by Provider',
          data:  this.dataByThreat
        }
      ]
    });
  }
}

