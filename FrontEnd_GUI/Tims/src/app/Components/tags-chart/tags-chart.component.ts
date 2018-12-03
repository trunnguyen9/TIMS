import { Component, OnInit } from '@angular/core';
import {Observable} from 'rxjs';
import {Chart} from 'angular-highcharts';
import {StatisticService} from '../../Services/statistic.service';
import {Router} from '@angular/router';

@Component({
  selector: 'app-tags-chart',
  templateUrl: './tags-chart.component.html',
  styleUrls: ['./tags-chart.component.css']
})
export class TagsChartComponent implements OnInit {

  dataByTagsObservable: Observable<any>;
  dataByTags;
  chart: Chart;
  constructor(private statistic: StatisticService, private router: Router) { }

  ngOnInit() {
    this.getDataByTags();
  }

  getDataByTags() {
    this.dataByTagsObservable = this.statistic.getStatisticByTags();
    this.dataByTagsObservable.subscribe(
      (data) => {
        this.dataByTags = data;
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
        type: 'pie',
        options3d: {
          enabled: true,
          alpha: 45,
          beta: 0
        }
      },
      title: {
        text: 'Tags Chart'
      },
      tooltip: {
        pointFormat: '{series.name}: <b>{point.percentage:.1f}%</b>'
      },
      plotOptions: {
        pie: {
          allowPointSelect: true,
          cursor: 'pointer',
          depth: 35,
          dataLabels: {
            enabled: true,
            format: '{point.name}'
          }
        }
      },
      series: [
        {
          type: 'pie',
          name: 'Tags Chart',
          data:  this.dataByTags
        }
      ]
    });
  }
}
