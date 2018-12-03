import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { ThreatChartComponent } from './threat-chart.component';

describe('ThreatChartComponent', () => {
  let component: ThreatChartComponent;
  let fixture: ComponentFixture<ThreatChartComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ ThreatChartComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(ThreatChartComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
